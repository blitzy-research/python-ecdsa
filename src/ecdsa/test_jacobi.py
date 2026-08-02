import pickle
import sys

try:
    import unittest2 as unittest
except ImportError:
    import unittest

import os
import signal
import pytest
import threading
import platform
import hypothesis.strategies as st
from hypothesis import given, assume, settings, example

from .ellipticcurve import CurveFp, PointJacobi, INFINITY, Point
from .ellipticcurve import GMPY, PointEdwards, _MUL_WINDOW

from .ecdsa import (
    generator_256,
    curve_256,
    generator_224,
    generator_brainpoolp160r1,
    curve_brainpoolp160r1,
    generator_112r2,
    curve_112r2,
)
from .numbertheory import inverse_mod
from .util import randrange
from ._compat import bit_length
from .eddsa import generator_ed25519


NO_OLD_SETTINGS = {}
if sys.version_info > (2, 7):  # pragma: no branch
    NO_OLD_SETTINGS["deadline"] = 5000


SLOW_SETTINGS = {}
if "--fast" in sys.argv:  # pragma: no cover
    SLOW_SETTINGS["max_examples"] = 2
else:
    SLOW_SETTINGS["max_examples"] = 10


def _ladder_window(order):
    """
    Return the digit width the fixed length ladder of `order` uses, or zero.

    Derived here from the rule rather than read off the implementation, for
    the same reason `_ladder_shape()` derives its own figures.  Two conditions
    have to hold.  The order has to be known and odd, because normalising a
    multiplier adds a whole number of orders to its residue to make that
    residue odd, and no multiple of an even order ever changes a parity.  And
    the order has to be above the largest digit the recoding can produce,
    ``2 ** window - 1``, because otherwise one of the odd multiples a
    multiplication table holds is a multiple of the order -- the point at
    infinity, which the affine entries of such a table cannot represent.
    There is one width to check, the single width the module recodes at.
    """
    order = int(order or 0)
    if not order or not order % 2:
        return 0
    if order <= (1 << _MUL_WINDOW) - 1:
        return 0
    return _MUL_WINDOW


def _ladder_shape(order):
    """
    Return the shape of the fixed length ladder of a point of `order`.

    The returned tuple holds the number of digits a multiplier is recoded
    into and the number of entries the multiplication table of a generator
    point therefore has.  Both follow the order of the point alone, which is
    public.

    Derived here from the order and the window alone, without asking the
    implementation: a canonical multiplier is odd and below three times the
    order, so it is below ``2 ** (bit_length(order) + 2)``, and the positions
    split that width into as few whole windows as possible.  Every position
    holds the odd multiples of a whole window, the most significant one
    included, so that the work of a position does not tell which position it
    is.  Deriving the shape from `PointJacobi._fixed_digit_count()` instead
    would make the tests below agree with the implementation by construction
    and so let a wrong count pass unnoticed.
    """
    window = _ladder_window(order)
    order = int(order)
    width = bit_length(order) + 2
    digits = width // window + (1 if width % window else 0)
    entries = digits * (1 << (window - 1))
    return digits, entries


class _CountedOperations(object):
    """
    Count the point additions and doublings of the block it wraps.

    The counters replace the methods of `point_class` for the duration of the
    `with` block only and are removed again in a `finally`, so that no other
    test, and no other caller in the process, sees a patched class.

    Counting operations keeps the assertions of the tests that use this
    deterministic; the wall clock is not used, and the number of operations is
    the quantity the ladders are written to keep independent of a multiplier.
    """

    def __init__(self, point_class):
        self.point_class = point_class
        self.additions = 0
        self.doublings = 0
        self._originals = {}

    def counts(self):
        """Return the additions and the doublings counted so far."""
        return self.additions, self.doublings

    def _wrap(self, name, bump):
        original = self.point_class.__dict__[name]
        self._originals[name] = original

        def counter(*args, **kwargs):
            bump()
            return original(*args, **kwargs)

        setattr(self.point_class, name, counter)

    def _bump_additions(self):
        self.additions += 1

    def _bump_doublings(self):
        self.doublings += 1

    def __enter__(self):
        try:
            self._wrap("_add", self._bump_additions)
            self._wrap("_double", self._bump_doublings)
        except Exception:  # pragma: no cover
            self.__exit__(None, None, None)
            raise
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        try:
            for name, original in self._originals.items():
                setattr(self.point_class, name, original)
        finally:
            self._originals = {}
        return False


class _CountedFormulas(object):
    """
    Count the individual coordinate formulas of the block it wraps.

    `_CountedOperations` counts the two dispatchers, `_add()` and `_double()`.
    This counts what they dispatch to as well, which is the finer question of
    whether a multiplier can steer a ladder into a different formula: an
    addition of two equal points is answered by a doubling formula instead,
    and a count of the dispatchers alone cannot see that substitution because
    the dispatcher was still entered exactly once.

    The methods of `point_class` are replaced for the duration of the `with`
    block only and restored in a `finally`, so that no other test, and no
    other caller in the process, sees a patched class.
    """

    JACOBI = (
        "_add",
        "_add_with_z_1",
        "_add_with_z_eq",
        "_add_with_z2_1",
        "_add_with_z_ne",
        "_double",
        "_double_with_z_1",
    )

    def __init__(self, point_class, names):
        self.point_class = point_class
        self.names = tuple(names)
        self.calls = {}
        self._originals = {}

    def profile(self):
        """Return the call count of every watched formula, name ordered."""
        return tuple((name, self.calls[name]) for name in self.names)

    def _wrap(self, name):
        original = self.point_class.__dict__[name]
        self._originals[name] = original
        self.calls[name] = 0

        def counter(*args, **kwargs):
            self.calls[name] += 1
            return original(*args, **kwargs)

        setattr(self.point_class, name, counter)

    def __enter__(self):
        try:
            for name in self.names:
                self._wrap(name)
        except Exception:  # pragma: no cover
            self.__exit__(None, None, None)
            raise
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        try:
            for name, original in self._originals.items():
                setattr(self.point_class, name, original)
        finally:
            self._originals = {}
        return False


class TestJacobi(unittest.TestCase):
    def test___init__(self):
        curve = object()
        x = 2
        y = 3
        z = 1
        order = 4
        pj = PointJacobi(curve, x, y, z, order)

        self.assertEqual(pj.order(), order)
        self.assertIs(pj.curve(), curve)
        self.assertEqual(pj.x(), x)
        self.assertEqual(pj.y(), y)

    def test_add_with_different_curves(self):
        p_a = PointJacobi.from_affine(generator_256)
        p_b = PointJacobi.from_affine(generator_224)

        with self.assertRaises(ValueError):  # pragma: no branch
            p_a + p_b

    def test_compare_different_curves(self):
        self.assertNotEqual(generator_256, generator_224)

    def test_equality_with_non_point(self):
        pj = PointJacobi.from_affine(generator_256)

        self.assertNotEqual(pj, "value")

    def test_conversion(self):
        pj = PointJacobi.from_affine(generator_256)
        pw = pj.to_affine()

        self.assertEqual(generator_256, pw)

    def test_single_double(self):
        pj = PointJacobi.from_affine(generator_256)
        pw = generator_256.double()

        pj = pj.double()

        self.assertEqual(pj.x(), pw.x())
        self.assertEqual(pj.y(), pw.y())

    def test_double_with_zero_point(self):
        pj = PointJacobi(curve_256, 0, 0, 1)

        pj = pj.double()

        self.assertIs(pj, INFINITY)

    def test_double_with_zero_equivalent_point(self):
        pj = PointJacobi(curve_256, 0, 0, 0)

        pj = pj.double()

        self.assertIs(pj, INFINITY)

    def test_double_with_zero_equivalent_point_non_zero_z_non_zero_y(self):
        pj = PointJacobi(curve_256, 0, 1, curve_256.p())

        pj = pj.double()

        self.assertIs(pj, INFINITY)

    def test_double_with_zero_equivalent_point_non_zero_z(self):
        pj = PointJacobi(curve_256, 0, 0, curve_256.p())

        pj = pj.double()

        self.assertIs(pj, INFINITY)

    def test_compare_with_affine_point(self):
        pj = PointJacobi.from_affine(generator_256)
        pa = pj.to_affine()

        self.assertEqual(pj, pa)
        self.assertEqual(pa, pj)

    def test_to_affine_with_zero_point(self):
        pj = PointJacobi(curve_256, 0, 0, 0)

        pa = pj.to_affine()

        self.assertIs(pa, INFINITY)

    def test_add_with_affine_point(self):
        pj = PointJacobi.from_affine(generator_256)
        pa = pj.to_affine()

        s = pj + pa

        self.assertEqual(s, pj.double())

    def test_radd_with_affine_point(self):
        pj = PointJacobi.from_affine(generator_256)
        pa = pj.to_affine()

        s = pa + pj

        self.assertEqual(s, pj.double())

    def test_add_with_infinity(self):
        pj = PointJacobi.from_affine(generator_256)

        s = pj + INFINITY

        self.assertEqual(s, pj)

    def test_add_zero_point_to_affine(self):
        pa = PointJacobi.from_affine(generator_256).to_affine()
        pj = PointJacobi(curve_256, 0, 0, 0)

        s = pj + pa

        self.assertIs(s, pa)

    def test_multiply_by_zero(self):
        pj = PointJacobi.from_affine(generator_256)

        pj = pj * 0

        self.assertIs(pj, INFINITY)

    def test_zero_point_multiply_by_one(self):
        pj = PointJacobi(curve_256, 0, 0, 1)

        pj = pj * 1

        self.assertIs(pj, INFINITY)

    def test_multiply_by_one(self):
        pj = PointJacobi.from_affine(generator_256)
        pw = generator_256 * 1

        pj = pj * 1

        self.assertEqual(pj.x(), pw.x())
        self.assertEqual(pj.y(), pw.y())

    def test_multiply_by_two(self):
        pj = PointJacobi.from_affine(generator_256)
        pw = generator_256 * 2

        pj = pj * 2

        self.assertEqual(pj.x(), pw.x())
        self.assertEqual(pj.y(), pw.y())

    def test_rmul_by_two(self):
        pj = PointJacobi.from_affine(generator_256)
        pw = generator_256 * 2

        pj = 2 * pj

        self.assertEqual(pj, pw)

    def test_compare_non_zero_with_infinity(self):
        pj = PointJacobi.from_affine(generator_256)

        self.assertNotEqual(pj, INFINITY)

    def test_compare_non_zero_bad_scale_with_infinity(self):
        pj = PointJacobi(curve_256, 1, 1, 0)
        self.assertEqual(pj, INFINITY)

    def test_eq_x_0_on_curve_with_infinity(self):
        c_23 = CurveFp(23, 1, 1)
        pj = PointJacobi(c_23, 0, 1, 1)

        self.assertTrue(c_23.contains_point(0, 1))

        self.assertNotEqual(pj, INFINITY)

    def test_eq_y_0_on_curve_with_infinity(self):
        c_23 = CurveFp(23, 1, 1)
        pj = PointJacobi(c_23, 4, 0, 1)

        self.assertTrue(c_23.contains_point(4, 0))

        self.assertNotEqual(pj, INFINITY)

    def test_eq_with_same_x_different_y(self):
        c_23 = CurveFp(23, 1, 1)
        p_a = PointJacobi(c_23, 0, 22, 1)
        p_b = PointJacobi(c_23, 0, 1, 1)

        self.assertNotEqual(p_a, p_b)

    def test_compare_zero_point_with_infinity(self):
        pj = PointJacobi(curve_256, 0, 0, 0)

        self.assertEqual(pj, INFINITY)

    def test_compare_double_with_multiply(self):
        pj = PointJacobi.from_affine(generator_256)
        dbl = pj.double()
        mlpl = pj * 2

        self.assertEqual(dbl, mlpl)

    @settings(**SLOW_SETTINGS)
    @given(
        st.integers(
            min_value=0, max_value=int(generator_brainpoolp160r1.order() - 1)
        )
    )
    def test_multiplications(self, mul):
        pj = PointJacobi.from_affine(generator_brainpoolp160r1)
        pw = pj.to_affine() * mul

        pj = pj * mul

        self.assertEqual((pj.x(), pj.y()), (pw.x(), pw.y()))
        self.assertEqual(pj, pw)

    @settings(**SLOW_SETTINGS)
    @given(
        st.integers(
            min_value=0, max_value=int(generator_brainpoolp160r1.order() - 1)
        )
    )
    @example(0)
    @example(int(generator_brainpoolp160r1.order()))
    def test_precompute(self, mul):
        precomp = generator_brainpoolp160r1
        self.assertTrue(precomp._PointJacobi__precompute)
        pj = PointJacobi.from_affine(generator_brainpoolp160r1)

        a = precomp * mul
        b = pj * mul

        self.assertEqual(a, b)

    @settings(**SLOW_SETTINGS)
    @given(
        st.integers(
            min_value=1, max_value=int(generator_brainpoolp160r1.order() - 1)
        ),
        st.integers(
            min_value=1, max_value=int(generator_brainpoolp160r1.order() - 1)
        ),
    )
    @example(3, 3)
    def test_add_scaled_points(self, a_mul, b_mul):
        j_g = PointJacobi.from_affine(generator_brainpoolp160r1)
        a = PointJacobi.from_affine(j_g * a_mul)
        b = PointJacobi.from_affine(j_g * b_mul)

        c = a + b

        self.assertEqual(c, j_g * (a_mul + b_mul))

    @settings(**SLOW_SETTINGS)
    @given(
        st.integers(
            min_value=1, max_value=int(generator_brainpoolp160r1.order() - 1)
        ),
        st.integers(
            min_value=1, max_value=int(generator_brainpoolp160r1.order() - 1)
        ),
        st.integers(min_value=1, max_value=int(curve_brainpoolp160r1.p() - 1)),
    )
    def test_add_one_scaled_point(self, a_mul, b_mul, new_z):
        j_g = PointJacobi.from_affine(generator_brainpoolp160r1)
        a = PointJacobi.from_affine(j_g * a_mul)
        b = PointJacobi.from_affine(j_g * b_mul)

        p = curve_brainpoolp160r1.p()

        assume(inverse_mod(new_z, p))

        new_zz = new_z * new_z % p

        b = PointJacobi(
            curve_brainpoolp160r1,
            b.x() * new_zz % p,
            b.y() * new_zz * new_z % p,
            new_z,
        )

        c = a + b

        self.assertEqual(c, j_g * (a_mul + b_mul))

    @pytest.mark.slow
    @settings(**SLOW_SETTINGS)
    @given(
        st.integers(
            min_value=1, max_value=int(generator_brainpoolp160r1.order() - 1)
        ),
        st.integers(
            min_value=1, max_value=int(generator_brainpoolp160r1.order() - 1)
        ),
        st.integers(min_value=1, max_value=int(curve_brainpoolp160r1.p() - 1)),
    )
    @example(1, 1, 1)
    @example(3, 3, 3)
    @example(2, int(generator_brainpoolp160r1.order() - 2), 1)
    @example(2, int(generator_brainpoolp160r1.order() - 2), 3)
    def test_add_same_scale_points(self, a_mul, b_mul, new_z):
        j_g = PointJacobi.from_affine(generator_brainpoolp160r1)
        a = PointJacobi.from_affine(j_g * a_mul)
        b = PointJacobi.from_affine(j_g * b_mul)

        p = curve_brainpoolp160r1.p()

        assume(inverse_mod(new_z, p))

        new_zz = new_z * new_z % p

        a = PointJacobi(
            curve_brainpoolp160r1,
            a.x() * new_zz % p,
            a.y() * new_zz * new_z % p,
            new_z,
        )
        b = PointJacobi(
            curve_brainpoolp160r1,
            b.x() * new_zz % p,
            b.y() * new_zz * new_z % p,
            new_z,
        )

        c = a + b

        self.assertEqual(c, j_g * (a_mul + b_mul))

    def test_add_same_scale_points_static(self):
        j_g = generator_brainpoolp160r1
        p = curve_brainpoolp160r1.p()
        a = j_g * 11
        a.scale()
        z1 = 13
        x = PointJacobi(
            curve_brainpoolp160r1,
            a.x() * z1**2 % p,
            a.y() * z1**3 % p,
            z1,
        )
        y = PointJacobi(
            curve_brainpoolp160r1,
            a.x() * z1**2 % p,
            a.y() * z1**3 % p,
            z1,
        )

        c = a + a

        self.assertEqual(c, x + y)

    @pytest.mark.slow
    @settings(**SLOW_SETTINGS)
    @given(
        st.integers(
            min_value=1, max_value=int(generator_brainpoolp160r1.order() - 1)
        ),
        st.integers(
            min_value=1, max_value=int(generator_brainpoolp160r1.order() - 1)
        ),
        st.lists(
            st.integers(
                min_value=1, max_value=int(curve_brainpoolp160r1.p() - 1)
            ),
            min_size=2,
            max_size=2,
            unique=True,
        ),
    )
    @example(2, 2, [2, 1])
    @example(2, 2, [2, 3])
    @example(2, int(generator_brainpoolp160r1.order() - 2), [2, 3])
    @example(2, int(generator_brainpoolp160r1.order() - 2), [2, 1])
    def test_add_different_scale_points(self, a_mul, b_mul, new_z):
        j_g = PointJacobi.from_affine(generator_brainpoolp160r1)
        a = PointJacobi.from_affine(j_g * a_mul)
        b = PointJacobi.from_affine(j_g * b_mul)

        p = curve_brainpoolp160r1.p()

        assume(inverse_mod(new_z[0], p))
        assume(inverse_mod(new_z[1], p))

        new_zz0 = new_z[0] * new_z[0] % p
        new_zz1 = new_z[1] * new_z[1] % p

        a = PointJacobi(
            curve_brainpoolp160r1,
            a.x() * new_zz0 % p,
            a.y() * new_zz0 * new_z[0] % p,
            new_z[0],
        )
        b = PointJacobi(
            curve_brainpoolp160r1,
            b.x() * new_zz1 % p,
            b.y() * new_zz1 * new_z[1] % p,
            new_z[1],
        )

        c = a + b

        self.assertEqual(c, j_g * (a_mul + b_mul))

    def test_add_different_scale_points_static(self):
        j_g = generator_brainpoolp160r1
        p = curve_brainpoolp160r1.p()
        a = j_g * 11
        a.scale()
        z1 = 13
        x = PointJacobi(
            curve_brainpoolp160r1,
            a.x() * z1**2 % p,
            a.y() * z1**3 % p,
            z1,
        )
        z2 = 29
        y = PointJacobi(
            curve_brainpoolp160r1,
            a.x() * z2**2 % p,
            a.y() * z2**3 % p,
            z2,
        )

        c = a + a

        self.assertEqual(c, x + y)

    def test_add_different_points_same_scale_static(self):
        j_g = generator_brainpoolp160r1
        p = curve_brainpoolp160r1.p()
        a = j_g * 11
        a.scale()
        b = j_g * 12
        z = 13
        x = PointJacobi(
            curve_brainpoolp160r1,
            a.x() * z**2 % p,
            a.y() * z**3 % p,
            z,
        )
        y = PointJacobi(
            curve_brainpoolp160r1,
            b.x() * z**2 % p,
            b.y() * z**3 % p,
            z,
        )

        c = a + b

        self.assertEqual(c, x + y)

    def test_add_same_point_different_scale_second_z_1_static(self):
        j_g = generator_112r2
        p = curve_112r2.p()
        z = 11
        a = j_g * z
        a.scale()

        x = PointJacobi(
            curve_112r2,
            a.x() * z**2 % p,
            a.y() * z**3 % p,
            z,
        )
        y = PointJacobi(
            curve_112r2,
            a.x(),
            a.y(),
            1,
        )

        c = a + a

        self.assertEqual(c, x + y)

    def test_add_to_infinity_static(self):
        j_g = generator_112r2

        z = 11
        a = j_g * z
        a.scale()

        b = -a

        x = PointJacobi(
            curve_112r2,
            a.x(),
            a.y(),
            1,
        )
        y = PointJacobi(
            curve_112r2,
            b.x(),
            b.y(),
            1,
        )

        self.assertEqual(INFINITY, x + y)

    def test_add_point_3_times(self):
        j_g = PointJacobi.from_affine(generator_256)

        self.assertEqual(j_g * 3, j_g + j_g + j_g)

    def test_mul_without_order(self):
        j_g = PointJacobi(curve_256, generator_256.x(), generator_256.y(), 1)

        self.assertEqual(j_g * generator_256.order(), INFINITY)

    def test_mul_add_inf(self):
        j_g = PointJacobi.from_affine(generator_256)

        self.assertEqual(j_g, j_g.mul_add(1, INFINITY, 1))

    def test_mul_add_same(self):
        j_g = PointJacobi.from_affine(generator_256)

        self.assertEqual(j_g * 2, j_g.mul_add(1, j_g, 1))

    def test_mul_add_precompute(self):
        j_g = PointJacobi.from_affine(generator_brainpoolp160r1, True)
        b = PointJacobi.from_affine(j_g * 255, True)

        self.assertEqual(j_g * 256, j_g + b)
        self.assertEqual(j_g * (5 + 255 * 7), j_g * 5 + b * 7)
        self.assertEqual(j_g * (5 + 255 * 7), j_g.mul_add(5, b, 7))

    def test_mul_add_precompute_large(self):
        j_g = PointJacobi.from_affine(generator_brainpoolp160r1, True)
        b = PointJacobi.from_affine(j_g * 255, True)

        self.assertEqual(j_g * 256, j_g + b)
        self.assertEqual(
            j_g * (0xFF00 + 255 * 0xF0F0), j_g * 0xFF00 + b * 0xF0F0
        )
        self.assertEqual(
            j_g * (0xFF00 + 255 * 0xF0F0), j_g.mul_add(0xFF00, b, 0xF0F0)
        )

    def test_mul_add_to_mul(self):
        j_g = PointJacobi.from_affine(generator_256)

        a = j_g * 3
        b = j_g.mul_add(2, j_g, 1)

        self.assertEqual(a, b)

    def test_mul_add_differnt(self):
        j_g = PointJacobi.from_affine(generator_256)

        w_a = j_g * 2

        self.assertEqual(j_g.mul_add(1, w_a, 1), j_g * 3)

    def test_mul_add_slightly_different(self):
        j_g = PointJacobi.from_affine(generator_256)

        w_a = j_g * 2
        w_b = j_g * 3

        self.assertEqual(w_a.mul_add(1, w_b, 3), w_a * 1 + w_b * 3)

    def test_mul_add(self):
        j_g = PointJacobi.from_affine(generator_256)

        w_a = generator_256 * 255
        w_b = generator_256 * (0xA8 * 0xF0)
        j_b = j_g * 0xA8

        ret = j_g.mul_add(255, j_b, 0xF0)

        self.assertEqual(ret.to_affine(), w_a + w_b)

    def test_mul_add_zero(self):
        j_g = PointJacobi.from_affine(generator_256)

        w_a = generator_256 * 255
        w_b = generator_256 * (0 * 0xA8)

        j_b = j_g * 0xA8

        ret = j_g.mul_add(255, j_b, 0)

        self.assertEqual(ret.to_affine(), w_a + w_b)

    def test_mul_add_large(self):
        j_g = PointJacobi.from_affine(generator_256)
        b = PointJacobi.from_affine(j_g * 255)

        self.assertEqual(j_g * 256, j_g + b)
        self.assertEqual(
            j_g * (0xFF00 + 255 * 0xF0F0), j_g * 0xFF00 + b * 0xF0F0
        )
        self.assertEqual(
            j_g * (0xFF00 + 255 * 0xF0F0), j_g.mul_add(0xFF00, b, 0xF0F0)
        )

    def test_mul_add_with_infinity_as_result(self):
        j_g = PointJacobi.from_affine(generator_256)

        order = generator_256.order()

        b = PointJacobi.from_affine(generator_256 * 256)

        self.assertEqual(j_g.mul_add(order % 256, b, order // 256), INFINITY)

    def test_mul_add_without_order(self):
        j_g = PointJacobi(curve_256, generator_256.x(), generator_256.y(), 1)

        order = generator_256.order()

        w_b = generator_256 * 34
        w_b.scale()

        b = PointJacobi(curve_256, w_b.x(), w_b.y(), 1)

        self.assertEqual(j_g.mul_add(order % 34, b, order // 34), INFINITY)

    def test_mul_add_with_doubled_negation_of_itself(self):
        j_g = PointJacobi.from_affine(generator_256 * 17)

        dbl_neg = 2 * (-j_g)

        self.assertEqual(j_g.mul_add(4, dbl_neg, 2), INFINITY)

    @given(
        st.integers(min_value=0, max_value=int(generator_112r2.order() - 1)),
        st.integers(min_value=0, max_value=int(generator_112r2.order() - 1)),
        st.integers(min_value=0, max_value=int(generator_112r2.order() - 1)),
    )
    @example(693, 2, 3293)  # values that will hit all the conditions for NAF
    def test_mul_add_random(self, mul1, mul2, mul3):
        p_a = PointJacobi.from_affine(generator_112r2)
        p_b = generator_112r2 * mul2

        res = p_a.mul_add(mul1, p_b, mul3)

        self.assertEqual(res, p_a * mul1 + p_b * mul3)

    def test_equality(self):
        pj1 = PointJacobi(curve=CurveFp(23, 1, 1, 1), x=2, y=3, z=1, order=1)
        pj2 = PointJacobi(curve=CurveFp(23, 1, 1, 1), x=2, y=3, z=1, order=1)
        self.assertEqual(pj1, pj2)

    def test_equality_with_invalid_object(self):
        j_g = PointJacobi.from_affine(generator_256)

        self.assertNotEqual(j_g, 12)

    def test_equality_with_wrong_curves(self):
        p_a = PointJacobi.from_affine(generator_256)
        p_b = PointJacobi.from_affine(generator_224)

        self.assertNotEqual(p_a, p_b)

    def test_add_with_point_at_infinity(self):
        pj1 = PointJacobi(curve=CurveFp(23, 1, 1, 1), x=2, y=3, z=1, order=1)
        x, y, z = pj1._add(2, 3, 1, 5, 5, 0, 23)

        self.assertEqual((x, y, z), (2, 3, 1))

    def test_double_to_infinity(self):
        c_23 = CurveFp(23, 1, 1)
        p = PointJacobi(c_23, 11, 20, 1)
        p2 = p.double()
        self.assertEqual((p2.x(), p2.y()), (4, 0))
        self.assertNotEqual(p2, INFINITY)
        p3 = p2.double()
        self.assertEqual(p3, INFINITY)
        self.assertIs(p3, INFINITY)

    def test_double_to_x_0(self):
        c_23_2 = CurveFp(23, 1, 2)
        p = PointJacobi(c_23_2, 9, 2, 1)
        p2 = p.double()

        self.assertEqual((p2.x(), p2.y()), (0, 18))

    def test_mul_to_infinity(self):
        c_23 = CurveFp(23, 1, 1)
        p = PointJacobi(c_23, 11, 20, 1)
        p2 = p * 2
        self.assertEqual((p2.x(), p2.y()), (4, 0))
        self.assertNotEqual(p2, INFINITY)
        p3 = p2 * 2
        self.assertEqual(p3, INFINITY)
        self.assertIs(p3, INFINITY)

    def test_add_to_infinity(self):
        c_23 = CurveFp(23, 1, 1)
        p = PointJacobi(c_23, 11, 20, 1)
        p2 = p + p
        self.assertEqual((p2.x(), p2.y()), (4, 0))
        self.assertNotEqual(p2, INFINITY)
        p3 = p2 + p2
        self.assertEqual(p3, INFINITY)
        self.assertIs(p3, INFINITY)

    def test_mul_to_x_0(self):
        c_23 = CurveFp(23, 1, 1)
        p = PointJacobi(c_23, 9, 7, 1)

        p2 = p * 13
        self.assertEqual((p2.x(), p2.y()), (0, 22))

    def test_mul_to_y_0(self):
        c_23 = CurveFp(23, 1, 1)
        p = PointJacobi(c_23, 9, 7, 1)

        p2 = p * 14
        self.assertEqual((p2.x(), p2.y()), (4, 0))

    def test_add_to_x_0(self):
        c_23 = CurveFp(23, 1, 1)
        p = PointJacobi(c_23, 9, 7, 1)

        p2 = p * 12 + p
        self.assertEqual((p2.x(), p2.y()), (0, 22))

    def test_add_to_y_0(self):
        c_23 = CurveFp(23, 1, 1)
        p = PointJacobi(c_23, 9, 7, 1)

        p2 = p * 13 + p
        self.assertEqual((p2.x(), p2.y()), (4, 0))

    def test_add_diff_z_to_infinity(self):
        c_23 = CurveFp(23, 1, 1)
        p = PointJacobi(c_23, 9, 7, 1)

        c = p * 20 + p * 8
        self.assertIs(c, INFINITY)

    def test_pickle(self):
        pj = PointJacobi(curve=CurveFp(23, 1, 1, 1), x=2, y=3, z=1, order=1)
        self.assertEqual(pickle.loads(pickle.dumps(pj)), pj)

    @pytest.mark.slow
    @settings(**NO_OLD_SETTINGS)
    @pytest.mark.skipif(
        platform.python_implementation() == "PyPy",
        reason="threading on PyPy breaks coverage",
    )
    @given(st.integers(min_value=1, max_value=10))
    def test_multithreading(self, thread_num):  # pragma: no cover
        # ensure that generator's precomputation table is filled
        generator_112r2 * 2

        # create a fresh point that doesn't have a filled precomputation table
        gen = generator_112r2
        gen = PointJacobi(gen.curve(), gen.x(), gen.y(), 1, gen.order(), True)

        self.assertEqual(gen._PointJacobi__precompute, [])

        def runner(generator):
            order = generator.order()
            for _ in range(10):
                generator * randrange(order)

        threads = []
        for _ in range(thread_num):
            threads.append(threading.Thread(target=runner, args=(gen,)))

        for t in threads:
            t.start()

        runner(gen)

        for t in threads:
            t.join()

        self.assertEqual(
            gen._PointJacobi__precompute,
            generator_112r2._PointJacobi__precompute,
        )

    @pytest.mark.slow
    @pytest.mark.skipif(
        platform.system() == "Windows"
        or platform.python_implementation() == "PyPy",
        reason="there are no signals on Windows, and threading breaks coverage"
        " on PyPy",
    )
    def test_multithreading_with_interrupts(self):  # pragma: no cover
        thread_num = 10
        # ensure that generator's precomputation table is filled
        generator_112r2 * 2

        # create a fresh point that doesn't have a filled precomputation table
        gen = generator_112r2
        gen = PointJacobi(gen.curve(), gen.x(), gen.y(), 1, gen.order(), True)

        self.assertEqual(gen._PointJacobi__precompute, [])

        def runner(generator):
            order = generator.order()
            for _ in range(50):
                generator * randrange(order)

        def interrupter(barrier_start, barrier_end, lock_exit):
            # wait until MainThread can handle KeyboardInterrupt
            barrier_start.release()
            barrier_end.acquire()
            os.kill(os.getpid(), signal.SIGINT)
            lock_exit.release()

        threads = []
        for _ in range(thread_num):
            threads.append(threading.Thread(target=runner, args=(gen,)))

        barrier_start = threading.Lock()
        barrier_start.acquire()
        barrier_end = threading.Lock()
        barrier_end.acquire()
        lock_exit = threading.Lock()
        lock_exit.acquire()

        threads.append(
            threading.Thread(
                target=interrupter,
                args=(barrier_start, barrier_end, lock_exit),
            )
        )

        for t in threads:
            t.start()

        with self.assertRaises(KeyboardInterrupt):
            # signal to interrupter that we can now handle the signal
            barrier_start.acquire()
            barrier_end.release()
            runner(gen)
            # use the lock to ensure we never go past the scope of
            # assertRaises before the os.kill is called
            lock_exit.acquire()

        for t in threads:
            t.join()

        self.assertEqual(
            gen._PointJacobi__precompute,
            generator_112r2._PointJacobi__precompute,
        )

    def fresh_generator(self, generator, generator_flag=True):
        """Return a copy of `generator` whose table is not built yet."""
        return PointJacobi(
            generator.curve(),
            generator.x(),
            generator.y(),
            1,
            generator.order(),
            generator_flag,
        )

    def test_precompute_table_is_empty_before_the_first_use(self):
        # a fast counterpart of the assertion the multithreading tests make,
        # so that the mutation selector, which skips the slow ones, sees it
        point = self.fresh_generator(generator_112r2)

        self.assertIsInstance(point._PointJacobi__precompute, list)
        self.assertEqual(point._PointJacobi__precompute, [])

    def test_precompute_table_of_a_non_generator_stays_empty(self):
        point = self.fresh_generator(generator_112r2, False)

        product = point * 12345

        self.assertEqual(product, generator_112r2 * 12345)
        self.assertEqual(point._PointJacobi__precompute, [])

    def test_maybe_precompute_returns_nothing(self):
        point = self.fresh_generator(generator_112r2)

        # `PointJacobi.__mul__()` reads the attribute after the call, so the
        # method itself answers with nothing; the twisted Edwards one returns
        # its table instead
        self.assertIsNone(point._maybe_precompute())
        self.assertTrue(point._PointJacobi__precompute)

    def test_precompute_table_is_not_built_for_an_unusable_order(self):
        generator = generator_112r2
        # Twice the order of a point annihilates it just as its order does, so
        # it is a valid order to state, but it is even, and an even order
        # cannot be added to a multiplier to make it odd.  Such a point gets
        # no table and keeps the behaviour of the releases up to 0.19.1, the
        # same way the point of `test_mul_without_order` does.
        order = 2 * int(generator.order())
        self.assertEqual(PointJacobi._fixed_ladder_usable(order), False)
        point = PointJacobi(
            generator.curve(), generator.x(), generator.y(), 1, order, True
        )

        self.assertIsNone(point._maybe_precompute())
        self.assertEqual(point._PointJacobi__precompute, [])

        for multiplier in (0, 1, 2, 3, 12345, order - 1, order, order + 1):
            self.assertEqual(point * multiplier, generator * multiplier)
        self.assertEqual(point._PointJacobi__precompute, [])

    def test_precompute_table_shape(self):
        for generator in (generator_112r2, generator_brainpoolp160r1):
            point = self.fresh_generator(generator)
            _, entries = _ladder_shape(generator.order())

            point._maybe_precompute()
            table = point._PointJacobi__precompute

            self.assertEqual(len(table), entries)
            # two values per entry, the affine coordinates of a multiple of
            # the point
            self.assertEqual(sorted(set(len(entry) for entry in table)), [2])
            for coord_x, coord_y in table:
                self.assertTrue(
                    generator.curve().contains_point(coord_x, coord_y)
                )

    def test_precompute_table_shape_of_this_implementation(self):
        # Exact figures, so that a change of the window width or of the size
        # of the table is a deliberate one.
        self.assertEqual(_MUL_WINDOW, 4)
        for generator, entries in (
            (generator_112r2, 224),
            (generator_brainpoolp160r1, 328),
        ):
            point = self.fresh_generator(generator)

            point._maybe_precompute()

            self.assertEqual(len(point._PointJacobi__precompute), entries)

    def test_precompute_table_holds_the_odd_multiples_of_the_point(self):
        generator = generator_112r2
        point = self.fresh_generator(generator)
        plain = self.fresh_generator(generator, False)
        digits, entries = _ladder_shape(generator.order())

        point._maybe_precompute()
        table = point._PointJacobi__precompute

        offset = 0
        multiples = 1 << (_MUL_WINDOW - 1)
        for position in range(digits):
            for index in range(multiples):
                expected = plain * (
                    (2 * index + 1) << (position * _MUL_WINDOW)
                )
                self.assertEqual(
                    table[offset + index], (expected.x(), expected.y())
                )
            offset += multiples
        self.assertEqual(offset, entries)

    def test_precompute_table_is_installed_once(self):
        point = self.fresh_generator(generator_112r2)
        _, entries = _ladder_shape(generator_112r2.order())

        point * 3
        table = point._PointJacobi__precompute
        snapshot = list(table)

        for multiplier in (0, 1, 2, 12345, int(generator_112r2.order())):
            point * multiplier
            # the table is built into a local and installed by a single
            # assignment, so it is either empty or complete, never a
            # partially filled list that a later call finishes
            self.assertIs(point._PointJacobi__precompute, table)
            self.assertEqual(len(table), entries)
        self.assertEqual(table, snapshot)

    def test_precompute_tables_of_two_points_are_equal(self):
        # a fast counterpart of the assertion the multithreading tests make
        first = self.fresh_generator(generator_112r2)
        second = self.fresh_generator(generator_112r2)

        first._maybe_precompute()
        second._maybe_precompute()
        # the third table compared below is the one the shared generator of
        # `ecdsa.ecdsa` holds, and that one is built lazily, so whether it has
        # been built by now depends on which tests ran before this one.
        # Building it explicitly is what makes this test independent of that
        # order; asking for a multiplication instead would work only for as
        # long as multiplication happens to build the table before answering,
        # which is a detail of the ladder rather than a promise to this test
        generator_112r2._maybe_precompute()

        self.assertIsNot(
            first._PointJacobi__precompute,
            second._PointJacobi__precompute,
        )
        self.assertEqual(
            first._PointJacobi__precompute,
            second._PointJacobi__precompute,
        )
        self.assertEqual(
            first._PointJacobi__precompute,
            generator_112r2._PointJacobi__precompute,
        )

    def test_operation_count_of_the_first_multiplication(self):
        for generator in (generator_112r2, generator_brainpoolp160r1):
            point = self.fresh_generator(generator)
            digits, entries = _ladder_shape(generator.order())

            with _CountedOperations(PointJacobi) as counted:
                point * 12345

            # building the table performs one addition per entry but the first
            # of each digit position, `entries - digits` of them, and the
            # multiplication that follows adds one per digit, so the two
            # together come to one addition per entry
            self.assertEqual(
                counted.counts(),
                (entries, _MUL_WINDOW * (digits - 1) + 1),
            )
            self.assertEqual(len(point._PointJacobi__precompute), entries)

    def test_operation_count_of_building_the_table_alone(self):
        """
        The two halves of the count the first multiplication sees together.

        `test_operation_count_of_the_first_multiplication` above counts the
        table build and the multiplication that reads it as one number, which
        would let a build that did too little hide behind a read that did too
        much, and the other way round.  Split here: the build performs one
        addition per entry bar the one each digit position starts from, and
        every doubling the whole multiplication does; the read that follows
        performs one addition per digit and no doubling at all.
        """
        for generator in (generator_112r2, generator_brainpoolp160r1):
            point = self.fresh_generator(generator)
            digits, entries = _ladder_shape(generator.order())

            with _CountedOperations(PointJacobi) as counted:
                point._maybe_precompute()
            building = counted.counts()
            with _CountedOperations(PointJacobi) as counted:
                point * 12345
            reading = counted.counts()

            self.assertEqual(
                building,
                (entries - digits, _MUL_WINDOW * (digits - 1) + 1),
            )
            self.assertEqual(reading, (digits, 0))

    def test_operation_count_with_a_precompute_table(self):
        point = self.fresh_generator(generator_112r2)
        order = int(generator_112r2.order())
        digits, _ = _ladder_shape(order)
        # built by the first multiplication, not by the ones being counted
        point._maybe_precompute()

        counts = []
        for multiplier in (
            2,
            3,
            10,
            order - 1,
            order,
            order + 1,
            2 * order,
            1 << 8,
            order // 3,
            5 * order + 7,
        ):
            with _CountedOperations(PointJacobi) as counted:
                point * multiplier
            counts.append(counted.counts())

        # one addition per digit and no doubling at all, whatever the
        # multiplier was
        self.assertEqual(counts, [(digits, 0)] * len(counts))

    def test_operation_count_of_the_edge_multipliers(self):
        # Zero, one and the order itself run the very same ladder as every
        # other multiplier and cost exactly the same.  Answering any of them
        # ahead of the ladder would spend no point operation at all where every
        # other multiplier spends the fixed number, which is the short circuit
        # CVE-2024-23342 is about; and a multiplier of one is not hypothetical,
        # `ecdsa.keys.SigningKey.sign_number()` accepts any nonce from one up.
        order = int(generator_112r2.order())
        digits, _ = _ladder_shape(order)
        edges = (0, 1, 2, order - 1, order, order + 1)

        point = self.fresh_generator(generator_112r2)
        point._maybe_precompute()
        for multiplier in edges:
            with _CountedOperations(PointJacobi) as counted:
                point * multiplier
            self.assertEqual(counted.counts(), (digits, 0))

        # and the same without a table, where the ladder builds the odd
        # multiples it needs as it goes
        plain = self.fresh_generator(generator_112r2, False)
        table_less = (
            digits + (1 << (_MUL_WINDOW - 1)) - 1,
            (digits - 1) * _MUL_WINDOW + 1,
        )
        for multiplier in edges:
            with _CountedOperations(PointJacobi) as counted:
                plain * multiplier
            self.assertEqual(counted.counts(), table_less)

    def test_what_the_edge_multipliers_answer(self):
        order = int(generator_112r2.order())
        point = self.fresh_generator(generator_112r2)
        point._maybe_precompute()
        plain = self.fresh_generator(generator_112r2, False)

        for multiplied in (point, plain):
            self.assertEqual(multiplied * 0, INFINITY)
            self.assertEqual(multiplied * order, INFINITY)
            self.assertIs(multiplied * 1, multiplied)
            self.assertIs(multiplied * True, multiplied)
            self.assertEqual(multiplied * (order + 1), multiplied)
            self.assertIsNot(multiplied * (order + 1), multiplied)
            self.assertEqual(multiplied * 2, multiplied + multiplied)
            self.assertEqual(multiplied * (order - 1) + multiplied, INFINITY)

    def test_operation_count_without_a_precompute_table(self):
        order = int(generator_112r2.order())
        digits, _ = _ladder_shape(order)

        counts = []
        for multiplier in (
            2,
            3,
            10,
            order - 1,
            order,
            order + 1,
            2 * order,
            1 << 8,
            order // 3,
            5 * order + 7,
        ):
            point = self.fresh_generator(generator_112r2, False)
            with _CountedOperations(PointJacobi) as counted:
                point * multiplier
            counts.append(counted.counts())

        # the odd multiples of the point cost one doubling and
        # 2**(window - 1) - 1 additions, then every digit costs one addition
        # and every position but the most significant one a whole window of
        # doublings
        expected = (
            (1 << (_MUL_WINDOW - 1)) - 1 + digits,
            (digits - 1) * _MUL_WINDOW + 1,
        )
        self.assertEqual(counts, [expected] * len(counts))

    def test_operation_count_without_an_order(self):
        # A point that carries no order has no order to bring its multiplier to
        # a canonical width against, so the width comes from the curve, which
        # bounds by Hasse's theorem every order a point of it can have.  Every
        # multiplier that curve can hold therefore costs one and the same
        # count: the count of a point that knows its order and one addition
        # more, for the odd form the multiplier is recoded in and the
        # correction that brings the product back.  ECDH against a remote
        # public point decoded from an encoding, which carries no order, is
        # what reaches this.
        point = PointJacobi(
            curve_112r2, generator_112r2.x(), generator_112r2.y(), 1
        )
        width = PointJacobi._curve_scalar_width(curve_112r2)
        digits = PointJacobi._curve_digit_count(curve_112r2, _MUL_WINDOW)
        expected = (
            (1 << (_MUL_WINDOW - 1)) - 1 + digits + 1,
            (digits - 1) * _MUL_WINDOW + 1,
        )
        # a 112 bit field, so a bound of 113 bits and 29 digits of four
        self.assertEqual((width, digits, expected), (113, 29, (37, 113)))

        counts = []
        for multiplier in (
            16,
            31,
            1 << 20,
            (1 << 20) - 1,
            12345,
            0,
            1,
            int(generator_112r2.order()),
            (1 << width) - 1,
        ):
            with _CountedOperations(PointJacobi) as counted:
                point * multiplier
            counts.append(counted.counts())

        self.assertEqual(counts, [expected] * 9)

    def test_operation_count_of_a_multiplier_past_the_curve_bound(self):
        # A multiplier no group of the curve could hold, and a negative one,
        # cannot be recoded against the curve: the recoding reads bits off a
        # non-negative value, and bringing either inside the bound would need
        # the order this point does not have.  Both keep the ladder of releases
        # up to 0.19.1, whose point operation count follows the multiplier --
        # which is no exposure, a private key and a nonce being drawn from
        # `[1, order)`.
        point = PointJacobi(
            curve_112r2, generator_112r2.x(), generator_112r2.y(), 1
        )
        width = PointJacobi._curve_scalar_width(curve_112r2)

        counts = []
        for multiplier in (1 << width, (1 << width) + 1, -16, -(1 << 20)):
            with _CountedOperations(PointJacobi) as counted:
                point * multiplier
            counts.append(counted.counts())

        self.assertEqual(counts, [(1, 114), (2, 114), (1, 5), (1, 21)])
        # and they answer the same points the recoded path answers
        order = int(generator_112r2.order())
        for multiplier in (1 << width, (1 << width) + 1, -16, -(1 << 20)):
            self.assertEqual(
                point * multiplier, generator_112r2 * (multiplier % order)
            )

    def test_which_points_are_recoded_against_their_curve(self):
        # Only a point that knows no order and is not flagged as a curve
        # generator.  A point that knows a usable order is recoded against that
        # order, a point of an order the recoding cannot use keeps the ladder
        # of releases up to 0.19.1, and a point flagged as a generator without
        # an order cannot build the table its flag promises: those releases
        # refused it and so does this, at the same multipliers and not at the
        # two they answered ahead of the refusal.  All of it is read from the
        # point.
        x, y = generator_256.x(), generator_256.y()
        order = int(generator_256.order())
        cases = (
            (PointJacobi(curve_256, x, y, 1), True),
            (PointJacobi(curve_256, x, y, 1, order), False),
            (PointJacobi(curve_256, x, y, 1, order, True), False),
            (PointJacobi(curve_256, x, y, 1, None, True), False),
            (PointJacobi(curve_256, x, y, 1, 2 * order), False),
        )
        for point, expected in cases:
            self.assertEqual(point._curve_fixed_usable(12345), expected)

        flagged = PointJacobi(curve_256, x, y, 1, None, True)
        self.assertRaises(AssertionError, flagged.__mul__, 5)
        self.assertIs(flagged * 0, INFINITY)
        self.assertIs(flagged * 1, flagged)

    def test_the_parity_correction_costs_the_same_either_way(self):
        # A point that knows no order is multiplied by the odd form of its
        # multiplier, and this point is subtracted from that product; the
        # parity of the multiplier picks one of the two answers out by index
        # rather than by branch, so both parities cost the same pair.  The
        # products are asserted as well, so this covers the correction and not
        # only its cost.
        point = PointJacobi(curve_256, generator_256.x(), generator_256.y(), 1)

        counts = []
        for multiplier in (12344, 12345, 12346, 12347):
            with _CountedOperations(PointJacobi) as counted:
                product = point * multiplier
            counts.append(counted.counts())
            self.assertEqual(product, generator_256 * multiplier)

        self.assertEqual(counts, [(73, 257)] * 4)

    def test_counted_operations_restores_the_methods(self):
        added = PointJacobi.__dict__["_add"]
        doubled = PointJacobi.__dict__["_double"]
        expected = generator_112r2 * 3

        with _CountedOperations(PointJacobi) as counted:
            self.assertIsNot(PointJacobi.__dict__["_add"], added)
            self.assertIsNot(PointJacobi.__dict__["_double"], doubled)
            # counting is transparent: the arguments and the result of every
            # operation pass through untouched
            self.assertEqual(generator_112r2 * 3, expected)
        self.assertNotEqual(counted.counts(), (0, 0))
        self.assertEqual(generator_112r2 * 3, expected)

        # the counters of this module are strictly local to the block that
        # installs them
        self.assertIs(PointJacobi.__dict__["_add"], added)
        self.assertIs(PointJacobi.__dict__["_double"], doubled)

    def test_getstate_is_the_plain_instance_dictionary(self):
        """
        The writer is left exactly as releases up to 0.19.1 wrote it.

        A copy of the instance dictionary, multiplication table and all.  It is
        `__setstate__()` alone that gained a test, so that a state written by
        one of those releases is not indexed with a layout it does not have;
        the writer is deliberately not narrowed, because narrowing it would
        change what a serialised point of this class means.
        """
        point = self.fresh_generator(generator_112r2)
        _, entries = _ladder_shape(generator_112r2.order())
        point._maybe_precompute()
        self.assertEqual(len(point._PointJacobi__precompute), entries)

        state = point.__getstate__()

        # exactly the keys releases up to 0.19.1 serialised, so that a release
        # reading this state finds every attribute it expects to find
        self.assertEqual(
            sorted(state.keys()),
            [
                "_PointJacobi__coords",
                "_PointJacobi__curve",
                "_PointJacobi__generator",
                "_PointJacobi__order",
                "_PointJacobi__precompute",
            ],
        )
        # a copy of the dictionary, so every value is the very object the
        # instance holds -- the table included -- and none of them was replaced
        self.assertIsNot(state, point.__dict__)
        self.assertEqual(state, point.__dict__)
        for key in state:
            self.assertIs(state[key], point.__dict__[key], key)
        self.assertEqual(len(state["_PointJacobi__precompute"]), entries)

    def test_pickle_of_a_point_with_a_precompute_table(self):
        # the point `test_pickle` uses carries no table, so the round trip of
        # one that does is checked here
        point = self.fresh_generator(generator_112r2)
        digits, entries = _ladder_shape(generator_112r2.order())
        point._maybe_precompute()
        table = list(point._PointJacobi__precompute)
        self.assertEqual(len(table), entries)

        restored = pickle.loads(pickle.dumps(point))

        self.assertEqual(restored, point)
        # the table travelled with the point and was recognised on the way in,
        # entry for entry, so nothing had to be rebuilt
        self.assertEqual(restored._PointJacobi__precompute, table)
        with _CountedOperations(PointJacobi) as counted:
            product = restored * 12345
        self.assertEqual(product, point * 12345)
        # the first multiplication of the restored point therefore costs what a
        # multiplication of the point it was made from costs, one addition per
        # digit and no doubling at all
        self.assertEqual(counted.counts(), (digits, 0))
        self.assertEqual(restored._PointJacobi__precompute, table)
        # and so does the next
        with _CountedOperations(PointJacobi) as counted:
            self.assertEqual(restored * 12345, product)
        self.assertEqual(counted.counts(), (digits, 0))

    def test_a_state_written_here_carries_a_table_of_this_layout(self):
        """
        The direction `__setstate__()` cannot guard: this release to an older.

        `__setstate__()` drops a restored table whose layout this code does not
        index, which is what makes a state written by an earlier release safe
        to load here.  The reverse cannot be arranged from here at all.  The
        state is the plain instance dictionary those releases wrote, so it
        carries a table of this layout; a release that indexes the table as the
        successive doublings of the point has no test to tell one layout from
        another, and would read this one as though it were that one and answer
        with a wrong point.  No code in this release runs on that side of the
        exchange.

        This test is that residual written down rather than an assertion of a
        property: what it pins is that the state does carry the table, that the
        two layouts differ in length as well as in contents, and that the entry
        an older release would read as twice the point is three times it here.
        It is recorded in `SECURITY.md` as accepted, and it is inherent to
        changing the layout of a cache a serialised point has always carried --
        the alternative, emptying the entry on the way out, would narrow a
        serialisation format every release of this library has read and
        written.
        """
        generator = generator_112r2
        _, entries = _ladder_shape(generator.order())
        warm = self.fresh_generator(generator)
        warm._maybe_precompute()
        old_format = self.old_format_precompute(generator)

        state = warm.__getstate__()

        # the table is in the state, of this layout
        self.assertEqual(
            state["_PointJacobi__precompute"], warm._PointJacobi__precompute
        )
        self.assertEqual(len(state["_PointJacobi__precompute"]), entries)
        # what an older release did on the way in, and nothing more: a bare
        # update of the instance dictionary, its own table build guarded on the
        # attribute being false -- which it is not, so it would index this one
        restored = PointJacobi.__new__(PointJacobi)
        restored.__dict__.update(state)
        self.assertTrue(restored._PointJacobi__precompute)
        # the point itself arrives whole either way
        self.assertEqual(restored, warm)
        self.assertEqual(
            (restored.x(), restored.y()), (generator.x(), generator.y())
        )
        self.assertEqual(restored._PointJacobi__order, generator.order())
        self.assertTrue(restored._PointJacobi__generator)
        # the two layouts are not interchangeable, which is the whole of the
        # residual: they differ in length
        self.assertEqual(len(old_format), bit_length(generator.order()) + 3)
        self.assertNotEqual(len(old_format), entries)
        self.assertNotEqual(warm._PointJacobi__precompute, old_format)
        # and in what each entry holds -- the entry an older release reads as
        # twice the point is three times it here
        plain = self.fresh_generator(generator, False)
        twice, thrice = plain * 2, plain * 3
        self.assertEqual(old_format[1], (twice.x(), twice.y()))
        self.assertEqual(
            warm._PointJacobi__precompute[1], (thrice.x(), thrice.y())
        )

    def old_format_precompute(self, generator):
        """Return a table of the layout the successive doubling ladder used."""
        point = self.fresh_generator(generator, False)
        table = []
        for _ in range(bit_length(generator.order()) + 3):
            table.append((point.x(), point.y()))
            point = point.double()
        return table

    def test_setstate_discards_an_old_format_precompute_table(self):
        generator = generator_112r2
        _, entries = _ladder_shape(generator.order())
        old_format = self.old_format_precompute(generator)
        self.assertEqual(len(old_format), bit_length(generator.order()) + 3)
        self.assertNotEqual(len(old_format), entries)
        state = self.fresh_generator(generator).__getstate__()
        state["_PointJacobi__precompute"] = old_format

        restored = PointJacobi.__new__(PointJacobi)
        restored.__setstate__(state)

        # a table of a layout the ladder no longer reads is dropped, not read
        self.assertEqual(restored._PointJacobi__precompute, [])
        self.assertEqual(restored * 12345, generator * 12345)
        self.assertEqual(len(restored._PointJacobi__precompute), entries)
        reference = self.fresh_generator(generator)
        reference._maybe_precompute()
        self.assertEqual(
            restored._PointJacobi__precompute,
            reference._PointJacobi__precompute,
        )

    def test_setstate_keeps_a_table_of_the_current_layout(self):
        generator = generator_112r2
        digits, entries = _ladder_shape(generator.order())
        warm = self.fresh_generator(generator)
        warm._maybe_precompute()
        state = warm.__getstate__()
        # the table `__getstate__()` put in the state, copied so that keeping
        # it cannot be confused with sharing the very list the warm point holds
        state["_PointJacobi__precompute"] = list(warm._PointJacobi__precompute)
        self.assertEqual(len(state["_PointJacobi__precompute"]), entries)

        restored = PointJacobi.__new__(PointJacobi)
        restored.__setstate__(state)

        # the one table that is not discarded: as many entries as this layout
        # builds, each a pair, for an order the recoding can use
        self.assertEqual(
            restored._PointJacobi__precompute,
            warm._PointJacobi__precompute,
        )
        with _CountedOperations(PointJacobi) as counted:
            product = restored * 12345
        self.assertEqual(product, generator * 12345)
        self.assertEqual(counted.counts(), (digits, 0))

    def test_setstate_discards_a_table_of_the_wrong_length(self):
        generator = generator_112r2
        _, entries = _ladder_shape(generator.order())
        template = self.fresh_generator(generator).__getstate__()

        # one entry too few would run off the end of the list, one too many
        # would answer with a wrong point; neither is read
        for length in (entries - 1, entries + 1, entries + 4):
            state = dict(template)
            state["_PointJacobi__precompute"] = [(1, 2)] * length

            restored = PointJacobi.__new__(PointJacobi)
            restored.__setstate__(state)

            self.assertEqual(restored._PointJacobi__precompute, [])
            self.assertEqual(restored * 12345, generator * 12345)
            self.assertEqual(len(restored._PointJacobi__precompute), entries)

    def test_setstate_discards_a_table_of_an_unusable_order(self):
        # an order the fixed length recoding cannot use indexes no table at
        # all, so a table carried for one is of no layout this code knows
        state = self.fresh_generator(generator_112r2).__getstate__()
        state["_PointJacobi__order"] = 5
        state["_PointJacobi__precompute"] = [(1, 2)] * 9

        restored = PointJacobi.__new__(PointJacobi)
        restored.__setstate__(state)

        self.assertEqual(restored._PointJacobi__precompute, [])

    def test_setstate_tolerates_a_malformed_precompute_table(self):
        generator = generator_112r2
        _, entries = _ladder_shape(generator.order())
        template = self.fresh_generator(generator).__getstate__()

        for table in (
            [],
            [(1,)] * entries,
            [(1, 2, 3)] * entries,
            [1] * entries,
            None,
            17,
            "junk",
        ):
            state = dict(template)
            state["_PointJacobi__precompute"] = table

            restored = PointJacobi.__new__(PointJacobi)
            # an unrecognised cache is not a broken pickle, so no state is
            # malformed enough to raise
            restored.__setstate__(state)

            self.assertEqual(restored._PointJacobi__precompute, [])
            self.assertEqual(restored * 12345, generator * 12345)
            self.assertEqual(len(restored._PointJacobi__precompute), entries)

    def test_setstate_without_a_precompute_table(self):
        generator = generator_112r2
        _, entries = _ladder_shape(generator.order())
        state = self.fresh_generator(generator).__getstate__()
        del state["_PointJacobi__precompute"]

        restored = PointJacobi.__new__(PointJacobi)
        restored.__setstate__(state)

        self.assertEqual(restored._PointJacobi__precompute, [])
        self.assertEqual(restored * 12345, generator * 12345)
        self.assertEqual(len(restored._PointJacobi__precompute), entries)

    def test_setstate_without_an_order(self):
        # the order is what says which layout a table would have, so a state
        # carrying none is answered like any other this code cannot index
        warm = self.fresh_generator(generator_112r2)
        warm._maybe_precompute()
        state = warm.__getstate__()
        # a table of the current layout, which would be kept if the order were
        # there to size it, see `test_setstate_keeps_a_table_of_the_current_
        # layout`
        self.assertTrue(state["_PointJacobi__precompute"])
        del state["_PointJacobi__order"]

        restored = PointJacobi.__new__(PointJacobi)
        restored.__setstate__(state)

        self.assertEqual(restored._PointJacobi__precompute, [])


class TestZeroCurve(unittest.TestCase):
    """Tests with curve that has (0, 0) on the curve."""

    def setUp(self):
        self.curve = CurveFp(23, 1, 0)

    def test_zero_point_on_curve(self):
        self.assertTrue(self.curve.contains_point(0, 0))

    def test_double_to_0_0_point(self):
        p = PointJacobi(self.curve, 1, 18, 1)

        d = p.double()

        self.assertNotEqual(d, INFINITY)
        self.assertEqual((0, 0), (d.x(), d.y()))

    def test_double_to_0_0_point_with_non_one_z(self):
        z = 2
        p = PointJacobi(self.curve, 1 * z**2, 18 * z**3, z)

        d = p.double()

        self.assertNotEqual(d, INFINITY)
        self.assertEqual((0, 0), (d.x(), d.y()))

    def test_mul_to_0_0_point(self):
        p = PointJacobi(self.curve, 11, 13, 1)

        d = p * 12

        self.assertNotEqual(d, INFINITY)
        self.assertEqual((0, 0), (d.x(), d.y()))

    def test_double_of_0_0_point(self):
        p = PointJacobi(self.curve, 0, 0, 1)

        d = p.double()

        self.assertIs(d, INFINITY)

    def test_compare_to_old_implementation(self):
        p = PointJacobi(self.curve, 11, 13, 1)
        p_c = Point(self.curve, 11, 13)

        for i in range(24):
            self.assertEqual(p * i, p_c * i)


class TestFixedLengthRecoding(unittest.TestCase):
    """
    Tests of how a multiplier is normalised and recoded for the ladders.

    `PointJacobi.__mul__()` brings its multiplier to a canonical form and
    recodes that into a fixed length sequence of non-zero signed digits, which
    is what lets a multiplication perform a number of point operations that
    follows the (public) order of the point rather than the multiplier.  The
    report of the work performed following the multiplier instead is
    CVE-2024-23342 (GHSA-wj6h-64fc-37mp).  The recoding is a group of static
    methods of `AbstractPoint`, reached here -- and by the twisted Edwards
    implementation -- through `PointJacobi`.

    `_naf()` is deliberately kept for `mul_add()` and for the points whose
    order cannot drive the fixed length recoding, so its digits are pinned
    down here too.
    """

    def orders(self):
        """Return the orders the recoding is exercised against."""
        return (
            # the narrowest order the fixed length recoding accepts, which
            # `test_fixed_ladder_usable_rejects_unusable_orders()` pins as
            # such, and two small ones that are easy to check by hand
            17,
            19,
            89,
            int(generator_112r2.order()),
            int(generator_brainpoolp160r1.order()),
            int(generator_224.order()),
            int(generator_256.order()),
            int(generator_ed25519.order()),
        )

    def test_naf_of_small_multipliers(self):
        self.assertEqual(PointJacobi._naf(0), [])
        self.assertEqual(PointJacobi._naf(1), [1])
        self.assertEqual(PointJacobi._naf(2), [0, 1])
        self.assertEqual(PointJacobi._naf(3), [-1, 0, 1])
        self.assertEqual(PointJacobi._naf(7), [-1, 0, 0, 1])
        self.assertEqual(PointJacobi._naf(8), [0, 0, 0, 1])
        self.assertEqual(PointJacobi._naf(255), [-1, 0, 0, 0, 0, 0, 0, 0, 1])

    def test_naf_digits_reconstruct_the_multiplier(self):
        for multiplier in range(300):
            digits = PointJacobi._naf(multiplier)

            for digit in digits:
                self.assertTrue(digit in (-1, 0, 1))
            self.assertEqual(
                sum(
                    digit * (1 << position)
                    for position, digit in enumerate(digits)
                ),
                multiplier,
            )
            # the sequence is in canonical form: no leading zero digit, and
            # no two adjacent non-zero ones.  Its length, and the number of
            # non-zero digits in it, both follow the multiplier, which the
            # paths still driven by it inherit: `mul_add()`, whose multipliers
            # come from a signature and are public, and a point of an order
            # the fixed length recoding cannot use.  No multiplication of a
            # secret reaches either -- signing, key generation and EdDSA
            # multiply ordered generators, and ECDH against a decoded remote
            # point is recoded against the curve of that point
            if multiplier:
                self.assertNotEqual(digits[-1], 0)
                for position in range(len(digits) - 1):
                    self.assertEqual(
                        digits[position] * digits[position + 1], 0
                    )
            else:
                self.assertEqual(digits, [])

    def test_fixed_ladder_usable_rejects_unusable_orders(self):
        # without an order there is nothing to normalise a multiplier against
        self.assertEqual(PointJacobi._fixed_ladder_usable(None), False)
        self.assertEqual(PointJacobi._fixed_ladder_usable(0), False)
        # an even order cannot be added to a multiplier to make it odd, so
        # there is no odd value congruent to an even multiplier to recode
        for order in (30, 32, 88, 256, 2 * 3 * 5 * 7 * 11):
            self.assertEqual(PointJacobi._fixed_ladder_usable(order), False)
        # an order no larger than the largest digit the recoding produces is
        # one where an odd multiple a multiplication table holds is a multiple
        # of the order, the point at infinity, which the affine entries of such
        # a table cannot represent
        for order in (1, 3, 5, 7, 9, 11, 13, 15):
            self.assertEqual(PointJacobi._fixed_ladder_usable(order), False)
        # from there up every odd order is accepted
        for order in (17, 19, 87, 89, 91, 101, 255, 1001):
            self.assertEqual(PointJacobi._fixed_ladder_usable(order), True)

    def test_fixed_window_has_one_width_and_a_floor(self):
        # There is one digit width, and a floor it puts under the orders it
        # can be used for: the largest digit the recoding produces is fifteen
        # at this width, so an order no larger than that would need an entry of
        # a multiplication table to hold the point at infinity.  Such an order
        # is left on the multiplier-driven ladder rather than recoded at a
        # narrower width -- a narrower width would admit it, its digits being
        # smaller, but a second width would make the width a point is recoded
        # at a property of its order.
        self.assertEqual(PointJacobi._fixed_window(None), 0)
        self.assertEqual(PointJacobi._fixed_window(0), 0)
        self.assertEqual(PointJacobi._fixed_window(1), 0)
        self.assertEqual(PointJacobi._fixed_window(13), 0)
        self.assertEqual(PointJacobi._fixed_window(15), 0)
        self.assertEqual(PointJacobi._fixed_window(16), 0)
        self.assertEqual(PointJacobi._fixed_window(17), _MUL_WINDOW)
        self.assertEqual(PointJacobi._fixed_window(18), 0)
        self.assertEqual(PointJacobi._fixed_window(19), _MUL_WINDOW)
        self.assertEqual(PointJacobi._fixed_window(87), _MUL_WINDOW)
        self.assertEqual(PointJacobi._fixed_window(88), 0)
        self.assertEqual(PointJacobi._fixed_window(89), _MUL_WINDOW)
        self.assertEqual(PointJacobi._fixed_window(101), _MUL_WINDOW)
        # the widths agree with a derivation of the rule that does not ask the
        # implementation, for every order up to a few hundred
        for order in range(0, 400):
            self.assertEqual(
                PointJacobi._fixed_window(order), _ladder_window(order), order
            )
            # and the only values it ever answers with are the one width and
            # the refusal
            self.assertIn(PointJacobi._fixed_window(order), (0, _MUL_WINDOW))

    def test_fixed_ladder_usable_accepts_the_curve_orders(self):
        for order in self.orders():
            self.assertEqual(PointJacobi._fixed_ladder_usable(order), True)
            self.assertEqual(PointJacobi._fixed_window(order), _MUL_WINDOW)

    def curve_orders(self):
        """
        Return the curves the curve-derived width is exercised against, each
        with the order its registered generator declares.
        """
        return tuple(
            (generator.curve(), int(generator.order()))
            for generator in (
                generator_112r2,
                generator_brainpoolp160r1,
                generator_224,
                generator_256,
            )
        )

    def test_curve_scalar_width_bounds_every_order_of_the_curve(self):
        """
        Hasse's bound, checked against rather than restated.

        The number of points of a curve over a field of ``p`` elements is
        within ``2 * sqrt(p)`` of ``p + 1``, and the order of any point divides
        that number, so no order of the curve reaches ``2 ** width``.  The
        check needs no square root: the root of ``p`` is below two raised to
        half its bit length rounded up, which bounds the Hasse maximum from
        above.  The declared order of each curve is one of those orders and is
        compared against the bound as well.
        """
        for curve, order in self.curve_orders():
            prime = int(curve.p())
            width = PointJacobi._curve_scalar_width(curve)
            root_bound = 1 << ((bit_length(prime) + 1) // 2)

            self.assertEqual(width, bit_length(prime) + 1)
            self.assertGreaterEqual(root_bound * root_bound, prime)
            self.assertGreater(1 << width, prime + 1 + 2 * root_bound)
            self.assertGreater(1 << width, order)

    def test_curve_digit_count_covers_the_curve_bound(self):
        for curve, _ in self.curve_orders():
            width = PointJacobi._curve_scalar_width(curve)
            for window in (1, 2, 3, 4, 5, 8):
                digits = PointJacobi._curve_digit_count(curve, window)
                # as few whole windows as hold the bound, and not one fewer
                self.assertGreaterEqual(digits * window, width)
                self.assertLess((digits - 1) * window, width)
        # and the counts of the module's own window, as literals: fields of
        # 112, 160, 224 and 256 bits, so bounds one bit wider than each
        self.assertEqual(
            [
                PointJacobi._curve_digit_count(curve, _MUL_WINDOW)
                for curve, _ in self.curve_orders()
            ],
            [29, 41, 57, 65],
        )

    def test_curve_ladder_usable_takes_what_the_curve_can_hold(self):
        for curve, order in self.curve_orders():
            width = PointJacobi._curve_scalar_width(curve)
            for multiplier in (
                0,
                1,
                2,
                order - 1,
                order,
                order + 1,
                (1 << width) - 1,
            ):
                self.assertEqual(
                    PointJacobi._curve_ladder_usable(curve, multiplier),
                    True,
                    multiplier,
                )
            # a value no group of the curve could hold, and a negative one:
            # neither is a value the recoding can read, and no secret of this
            # library is either
            for multiplier in (
                1 << width,
                (1 << width) + 1,
                1 << (width + 8),
                -1,
                -order,
            ):
                self.assertEqual(
                    PointJacobi._curve_ladder_usable(curve, multiplier),
                    False,
                    multiplier,
                )

    def _canonical_of(self, multiplier, order):
        """
        Return the value `_canonical_scalar()` has to answer with.

        Derived here by searching the interval every answer comes from rather
        than by repeating the arithmetic of the implementation, so that a wrong
        offset or a wrong interval fails these tests instead of being agreed
        with.

        The interval runs from the order up to three times it.  It holds
        exactly two values congruent to any given multiplier and, the order
        being odd, their parities differ, so exactly one of them is odd.  That
        one is the answer, and there is nothing to choose between.
        """
        order = int(order)
        residue = int(multiplier) % order
        odd = [
            value
            for value in (residue + order, residue + 2 * order)
            if value % 2
        ]
        self.assertEqual(len(odd), 1)
        return odd[0]

    def test_canonical_scalar_of_the_multiples_of_the_order(self):
        for order in self.orders():
            # A multiple of the order is congruent to zero, which is even, so
            # the parity correction adds a single order and the answer is the
            # order itself.
            for multiplier in (0, order, 2 * order, 7 * order):
                canonical = PointJacobi._canonical_scalar(multiplier, order)

                self.assertEqual(
                    canonical, self._canonical_of(multiplier, order)
                )
                self.assertEqual(canonical, order)
                self.assertEqual(canonical % order, 0)
                self.assertEqual(canonical % 2, 1)

    def test_canonical_scalar_of_the_edge_multipliers(self):
        # Exact values, on an order small enough to write them out.  An answer
        # for an order of eighty-nine is the residue plus one order where that
        # residue is even and plus two orders where it is odd, so it lies
        # between eighty-nine and two hundred and sixty-five and is seven,
        # eight or nine bits wide.  The width is deliberately not one value:
        # what a ladder is kept from following the multiplier through is the
        # number of digits, which the tests below pin.
        self.assertEqual(PointJacobi._canonical_scalar(0, 89), 89)
        self.assertEqual(PointJacobi._canonical_scalar(89, 89), 89)
        self.assertEqual(PointJacobi._canonical_scalar(1, 89), 179)
        self.assertEqual(PointJacobi._canonical_scalar(90, 89), 179)
        self.assertEqual(PointJacobi._canonical_scalar(88, 89), 177)
        self.assertEqual(PointJacobi._canonical_scalar(3, 89), 181)
        self.assertEqual(PointJacobi._canonical_scalar(2, 89), 91)
        # no residue of this order ends its ladder on two equal operands, a
        # case some orders do have and `_degenerate_residues()` finds
        self.assertEqual(self._degenerate_residues(89), [])
        # the narrowest order the recoding accepts is one that does
        self.assertEqual(self._degenerate_residues(17), [11])
        self.assertEqual(PointJacobi._canonical_scalar(11, 17), 45)

        # and on a real curve order, stated as the value it has to be
        order = int(generator_112r2.order())
        for multiplier in (0, 1, 2, order - 1, order + 1, order + 2, 30):
            self.assertEqual(
                PointJacobi._canonical_scalar(multiplier, order),
                self._canonical_of(multiplier, order),
            )

    def test_canonical_scalar_is_odd_and_congruent_to_the_multiplier(self):
        for order in self.orders():
            for multiplier in (
                0,
                1,
                2,
                3,
                10,
                22,
                1 << 8,
                order - 1,
                order,
                order + 1,
                2 * order,
                order // 3,
                5 * order + 7,
            ):
                canonical = PointJacobi._canonical_scalar(multiplier, order)

                # odd, because the recoding requires it, and congruent to the
                # multiplier, because adding a multiple of the order to a
                # multiplier does not change the product
                self.assertEqual(canonical % 2, 1)
                self.assertEqual(canonical % order, multiplier % order)
                # inside the one interval the digit count is sized from
                self.assertLessEqual(order, canonical)
                self.assertLess(canonical, 3 * order)
                # whose members are not all of one width: from the width of
                # the order up to two bits above it, decided by the residue.
                # One width is not asserted because it would be false, and
                # ``SECURITY.md`` records that residual; the digit count the
                # ladder spends is what is invariant.
                self.assertGreaterEqual(
                    bit_length(canonical), bit_length(order)
                )
                self.assertLessEqual(
                    bit_length(canonical), bit_length(3 * order - 2)
                )

    def test_canonical_scalar_is_the_only_odd_value_of_its_interval(self):
        # Two values of the interval every answer comes from are congruent to
        # a given multiplier, and because the order is odd their parities
        # differ, so exactly one of them is odd.  There is no choice to make,
        # so nothing about which value is answered with can follow anything
        # but the residue of the multiplier.
        for order in (17, 89, int(generator_112r2.order())):
            for multiplier in (0, 1, 2, 10, 22, 30, order - 1):
                canonical = PointJacobi._canonical_scalar(multiplier, order)

                residue = multiplier % order
                both = [residue + order, residue + 2 * order]
                odd = [value for value in both if value % 2]

                self.assertEqual(len(odd), 1)
                self.assertEqual(both[1] - both[0], order)
                self.assertEqual(canonical, odd[0])

    def _degenerate_residues(self, order):
        """
        Return the residues whose ladder ends on two equal operands, derived
        from the order without asking the implementation.

        The two operands of the last addition of a ladder coincide when the
        canonical multiplier is congruent to twice the digit of the lowest
        position, so the residues that can do it are twice a digit, and which
        of those actually do is settled by reading the lowest digit of the
        canonical form of each.  At most two residues of any order qualify and
        some orders, SECP160r1 among the curves this library registers, have
        none at all.
        """
        order = int(order)
        low_bits = 1 << (_MUL_WINDOW + 1)
        found = []
        for digit in range(-(1 << _MUL_WINDOW) + 1, 1 << _MUL_WINDOW, 2):
            residue = (2 * digit) % order
            canonical = self._canonical_of(residue, order)
            lowest = (canonical % low_bits) - (low_bits >> 1)
            if (canonical - 2 * lowest) % order == 0:
                found.append(residue)
        return sorted(set(found))

    def test_at_most_two_residues_of_an_order_are_degenerate(self):
        # A digit settles a residue and a residue settles a digit, so at most
        # one residue per digit can be degenerate, and reading the lowest digit
        # of the canonical form of each brings that down to two for any order
        # at all.  How many, and which, follows the order alone.
        for order in self.orders():
            self.assertLessEqual(len(self._degenerate_residues(order)), 2)
        self.assertEqual(self._degenerate_residues(89), [])
        self.assertEqual(self._degenerate_residues(17), [11])
        self.assertEqual(
            len(
                self._degenerate_residues(
                    int(generator_brainpoolp160r1.order())
                )
            ),
            2,
        )

    def test_which_canonical_scalars_end_a_ladder_on_equal_operands(self):
        # The residual `_canonical_scalar()` leaves, bounded rather than
        # removed: every residue that could possibly break the property is
        # checked, and only the ones `_degenerate_residues()` names do, so an
        # accumulator coincides with the point being added to it for at most
        # two multipliers of any order.  What that costs is measured in
        # `test_formula_dispatch_of_the_degenerate_residue()` below.
        low_bits = 1 << (_MUL_WINDOW + 1)

        for order in self.orders():
            degenerate = self._degenerate_residues(order)
            residues = set(
                (2 * digit) % order
                for digit in range(
                    -(1 << _MUL_WINDOW) + 1, 1 << _MUL_WINDOW, 2
                )
            )
            residues.update((0, 1, 2, order - 1))
            for residue in sorted(residues):
                canonical = PointJacobi._canonical_scalar(residue, order)

                lowest = (canonical % low_bits) - (low_bits >> 1)

                self.assertEqual(
                    (canonical - 2 * lowest) % order == 0,
                    residue % order in degenerate,
                    (order, residue),
                )
                if not residue % order:
                    # a multiplier that is a multiple of the order meets the
                    # negation of its addend instead, and that sum being the
                    # point at infinity is the correct answer
                    self.assertEqual(canonical % order, 0)
                    self.assertTrue(residue % order not in degenerate)

    def test_the_degenerate_residue_is_answered_correctly(self):
        # A residue that ends its ladder on two equal operands is answered with
        # the point every other route to it is answered with, and its canonical
        # form is the value every other residue's is.  Only the cost differs,
        # by one field level call, which the test below measures.
        for generator in (generator_brainpoolp160r1, generator_112r2):
            order = int(generator.order())
            residues = self._degenerate_residues(order)

            self.assertTrue(residues)
            for residue in residues:
                canonical = PointJacobi._canonical_scalar(residue, order)

                self.assertEqual(canonical % order, residue)
                self.assertEqual(canonical % 2, 1)
                self.assertLessEqual(order, canonical)
                self.assertLess(canonical, 3 * order)
                self.assertEqual(generator * residue, generator * canonical)

    def test_formula_dispatch_of_the_degenerate_residue(self):
        # What a residue that ends its ladder on two equal operands costs,
        # measured rather than assumed.  Neither of the two dispatchers the
        # operation counts elsewhere are taken from moves for it: the number of
        # `_add()` calls is the same and no `_double()` is added, because
        # `_add_with_z2_1()` answers that addition inside itself with
        # `_double_with_z_1()`.  The whole of the difference is that one field
        # level call, on either of the two fixed work paths, so the residual is
        # one call cheaper rather than one point operation more.
        generator = generator_brainpoolp160r1
        order = int(generator.order())
        residues = self._degenerate_residues(order)
        residue = residues[0]
        neighbours = (residue + 2, residue - 2, 20, 21)
        for multiplier in neighbours:
            self.assertTrue(multiplier % order not in residues)

        def profile_of(multiplier, precompute):
            point = PointJacobi(
                generator.curve(),
                generator.x(),
                generator.y(),
                1,
                order,
                precompute,
            )
            if precompute:
                point._maybe_precompute()
            with _CountedFormulas(
                PointJacobi, _CountedFormulas.JACOBI
            ) as counted:
                product = point * multiplier
                return counted.profile(), product

        for precompute in (True, False):
            degenerate, reference = profile_of(residue, precompute)
            plain = profile_of(neighbours[0], precompute)[0]
            for multiplier in neighbours[1:]:
                # every multiplier that is not one of the two costs the same
                self.assertEqual(profile_of(multiplier, precompute)[0], plain)

            counts = dict(plain)
            degenerate_counts = dict(degenerate)
            difference = sorted(
                (name, degenerate_counts[name] - count)
                for name, count in counts.items()
                if degenerate_counts[name] != count
            )
            self.assertEqual(difference, [("_double_with_z_1", 1)])
            self.assertEqual(degenerate_counts["_add"], counts["_add"])
            self.assertEqual(degenerate_counts["_double"], counts["_double"])
            # on the precomputed path the table is already built and nothing
            # legitimately doubles, so the one call above is the whole of it
            if precompute:
                self.assertEqual(counts["_double"], 0)
                self.assertEqual(counts["_double_with_z_1"], 0)
            self.assertEqual(reference, generator * residue)

    @settings(**SLOW_SETTINGS)
    @given(
        st.integers(
            min_value=0, max_value=int(generator_brainpoolp160r1.order() - 1)
        )
    )
    @example(0)
    @example(1)
    # the two residues of this order whose ladder ends on two equal operands
    @example(14)
    @example(int(generator_brainpoolp160r1.order()) - 22)
    @example(int(generator_brainpoolp160r1.order()))
    def test_canonical_scalar_does_not_change_the_product(self, multiplier):
        generator = generator_brainpoolp160r1
        order = int(generator.order())
        canonical = PointJacobi._canonical_scalar(multiplier, order)

        product = generator * multiplier

        self.assertEqual(product, generator * canonical)
        self.assertEqual(product, generator * (multiplier + order))
        self.assertEqual(product, generator * (multiplier + 2 * order))

    def test_digit_count_is_the_smallest_that_fits_a_canonical_scalar(self):
        window = _MUL_WINDOW

        for order in self.orders():
            count = PointJacobi._fixed_digit_count(order, window)

            # a canonical multiplier is below three times the order and so
            # below 2 ** (bit_length(order) + 2), so that many bits always
            # hold it, and not one digit more than that may be asked for
            self.assertGreaterEqual(count * window, bit_length(order) + 2)
            self.assertLess((count - 1) * window, bit_length(order) + 2)

    def test_every_position_of_the_table_holds_a_whole_window(self):
        # The most significant position is not trimmed to the bits the other
        # positions leave over: it holds the odd multiples of a whole window
        # like every other position, so that the work of reading a position
        # does not say which position was read.
        window = _MUL_WINDOW

        for order in self.orders():
            count = PointJacobi._fixed_digit_count(order, window)

            length = PointJacobi._fixed_table_length(order, window)

            self.assertEqual(length, count * (1 << (window - 1)))
            # exactly as many entries per position, none of them shared
            self.assertEqual(length % count, 0)
            self.assertEqual(length // count, 1 << (window - 1))

    def test_ladder_shape_of_the_curves(self):
        # Exact figures of this implementation.  They follow from the window
        # width it uses, so retuning that width means refreshing them.
        self.assertEqual(_MUL_WINDOW, 4)
        expected = (
            (generator_112r2, 28, 224),
            (generator_brainpoolp160r1, 41, 328),
            (generator_224, 57, 456),
            (generator_256, 65, 520),
            (generator_ed25519, 64, 512),
        )

        for generator, digits, entries in expected:
            order = generator.order()

            self.assertEqual(
                PointJacobi._fixed_digit_count(order, _MUL_WINDOW), digits
            )
            self.assertEqual(
                PointJacobi._fixed_table_length(order, _MUL_WINDOW), entries
            )
            self.assertEqual(_ladder_shape(order), (digits, entries))

    def test_fixed_digits_are_odd_and_narrower_than_the_window(self):
        window = _MUL_WINDOW

        for order in self.orders():
            count = PointJacobi._fixed_digit_count(order, window)
            for multiplier in (
                0,
                1,
                2,
                3,
                10,
                order - 1,
                order,
                order + 1,
                2 * order,
                order // 3,
                5 * order + 7,
            ):
                canonical = PointJacobi._canonical_scalar(multiplier, order)

                digits = PointJacobi._fixed_digits(canonical, count, window)

                self.assertEqual(len(digits), count)
                for digit in digits:
                    # a zero digit would be a position that costs no point
                    # addition, and so a multiplication whose cost follows the
                    # multiplier
                    self.assertEqual(digit % 2, 1)
                    self.assertNotEqual(digit, 0)
                    self.assertLess(abs(digit), 1 << window)
                self.assertEqual(
                    sum(
                        digit * (1 << (position * window))
                        for position, digit in enumerate(digits)
                    ),
                    canonical,
                )

    def test_fixed_digits_of_the_largest_canonical_scalar(self):
        window = _MUL_WINDOW

        for order in self.orders():
            count = PointJacobi._fixed_digit_count(order, window)
            # the largest value `_canonical_scalar()` can return still has to
            # fit in the digits `_fixed_digit_count()` asks for; the widest
            # answer comes from the largest odd residue, two below the order,
            # to which the parity correction adds two orders
            largest = 3 * order - 2

            digits = PointJacobi._fixed_digits(largest, count, window)

            self.assertEqual(len(digits), count)
            for digit in digits:
                self.assertLess(abs(digit), 1 << window)
            self.assertEqual(
                sum(
                    digit * (1 << (position * window))
                    for position, digit in enumerate(digits)
                ),
                largest,
            )

    def test_fixed_digits_are_deterministic(self):
        order = int(generator_112r2.order())
        count = PointJacobi._fixed_digit_count(order, _MUL_WINDOW)
        canonical = PointJacobi._canonical_scalar(12345, order)

        first = PointJacobi._fixed_digits(canonical, count, _MUL_WINDOW)
        second = PointJacobi._fixed_digits(canonical, count, _MUL_WINDOW)

        self.assertEqual(first, second)

    def test_fixed_digits_with_a_single_bit_window(self):
        # with a window of one bit the recoding degenerates into a signed
        # binary expansion with digits taken from -1 and 1
        digits = PointJacobi._fixed_digits(11, 5, 1)

        self.assertEqual(digits, [1, -1, 1, -1, 1])
        self.assertEqual(
            sum(
                digit * (1 << position)
                for position, digit in enumerate(digits)
            ),
            11,
        )

    def test_fixed_digits_of_one(self):
        # the smallest odd multiplier, which every position but the most
        # significant one answers with its most negative digit
        self.assertEqual(
            PointJacobi._fixed_digits(1, 4, 4), [-15, -15, -15, 1]
        )
        self.assertEqual(
            PointJacobi._fixed_digits(0xFFFF, 4, 4), [15, 15, 15, 15]
        )

    def test_the_helpers_answer_through_an_instance_too(self):
        """
        Every helper is reached as a static or class method, through both.

        `__mul__()` reads them off the class, and in Python 3 a plain function
        answers a class access exactly as a static method does, so a helper
        that lost its decorator would go unnoticed there.  An instance access
        is where the difference shows: a plain function reached through an
        instance receives the point in place of its first argument.  Both
        accesses are asserted, against the same exact values.
        """
        point = PointJacobi(curve_256, generator_256.x(), generator_256.y(), 1)
        order = int(generator_256.order())

        self.assertEqual(point._curve_scalar_width(curve_256), 257)
        self.assertEqual(
            point._curve_scalar_width(curve_256),
            PointJacobi._curve_scalar_width(curve_256),
        )
        self.assertEqual(point._curve_digit_count(curve_256, _MUL_WINDOW), 65)
        self.assertEqual(point._fixed_window(order), _MUL_WINDOW)
        self.assertEqual(point._fixed_ladder_usable(order), True)
        self.assertEqual(point._fixed_digit_count(order, _MUL_WINDOW), 65)
        self.assertEqual(point._fixed_table_length(order, _MUL_WINDOW), 520)
        self.assertEqual(point._canonical_scalar(2, order), 2 + order)
        self.assertEqual(point._fixed_digits(1, 4, 4), [-15, -15, -15, 1])
        self.assertEqual(point._integer_multiplier(True), 1)
        self.assertEqual(point._naf(5), [1, 0, 1])

    def test_the_shape_check_refuses_a_table_it_cannot_index(self):
        """
        The two halves of the check a restored table is put through.

        A table of no entries indexes nothing, and an entry holding the wrong
        number of coordinates cannot be unpacked, so neither is a table this
        layout would have written and neither may be kept.  The number of
        coordinates is compared by value rather than by identity, which an
        arity above the integers CPython keeps interned is what states: a
        table of 257 values per entry is answered on what the lengths are, not
        on whether they are the same object.
        """
        order = int(generator_brainpoolp160r1.order())
        length = PointJacobi._fixed_table_length(order, _MUL_WINDOW)

        self.assertEqual(PointJacobi._fixed_table_shaped([], order, 2), False)
        self.assertEqual(PointJacobi._fixed_table_shaped((), order, 2), False)
        self.assertEqual(
            PointJacobi._fixed_table_shaped([(1, 2)] * length, order, 2), True
        )
        self.assertEqual(
            PointJacobi._fixed_table_shaped([(1, 2, 3)] * length, order, 2),
            False,
        )

        narrow = 17
        wide = [tuple(range(257))] * PointJacobi._fixed_table_length(
            narrow, _MUL_WINDOW
        )

        self.assertEqual(len(wide), 16)
        self.assertEqual(len(wide[0]), 257)
        self.assertEqual(
            PointJacobi._fixed_table_shaped(wide, narrow, 257), True
        )
        self.assertEqual(
            PointJacobi._fixed_table_shaped(wide, narrow, 256), False
        )

    def test_batch_rescaling_answers_the_affine_form_of_every_point(self):
        """
        One modular inversion, and every coordinate a residue of the prime.

        The table `_mul_fixed()` rebuilds on every call is rescaled in one
        batch.  Each entry has to come back reduced modulo the field prime,
        not merely congruent to its residue: the addition formula the ladder
        reaches spots two equal operands by comparing raw coordinate
        differences, so a coordinate carrying a whole prime more than its
        residue would be read as a different point.  Asserted against the
        affine coordinates the same points scale to one at a time.
        """
        prime = curve_256.p()
        base = PointJacobi(curve_256, generator_256.x(), generator_256.y(), 1)
        points = [base * multiple for multiple in (1, 3, 5, 7)]
        raw = [point._PointJacobi__coords for point in points]

        scaled = PointJacobi._scaled_all(raw, prime)

        self.assertEqual(len(scaled), 4)
        for point, entry in zip(points, scaled):
            self.assertEqual(entry, (point.x(), point.y(), 1))
            for coordinate in entry:
                self.assertGreaterEqual(coordinate, 0)
                self.assertLess(coordinate, prime)

    def test_batch_rescaling_keeps_the_point_at_infinity(self):
        """
        A zero ``z`` counts as one in the product and comes back all zero.

        The odd multiple table of `_mul_fixed()` runs past the order of a low
        order point, so one of its entries can be the point at infinity, and a
        zero entering the product would take every other entry down with it.
        Stated with the point at infinity first, in the middle and last, since
        the product is accumulated forwards and unwound backwards.
        """
        prime = curve_256.p()
        base = PointJacobi(curve_256, generator_256.x(), generator_256.y(), 1)
        one, three = base * 1, base * 3
        affine = [(one.x(), one.y(), 1), (three.x(), three.y(), 1)]

        for position in (0, 1, 2):
            batch = list(affine)
            batch.insert(position, (0, 0, 0))

            scaled = PointJacobi._scaled_all(batch, prime)

            self.assertEqual(len(scaled), 3)
            self.assertEqual(scaled[position], (0, 0, 0))
            self.assertEqual(
                scaled[:position] + scaled[position + 1 :], affine
            )

    def test_the_table_less_ladder_at_a_wider_window(self):
        """
        The ladder honours the width it is handed, table and all.

        `_mul_fixed_digits()` takes its window as an argument and builds the
        ``2 ** (window - 1)`` odd multiples of that width before walking the
        digits.  A width wider than the one this module recodes at is stated
        here so that the count the build stops at follows the argument rather
        than any one value, and so that it is compared by value: the count of
        a wide window is above the integers CPython keeps interned.
        """
        order = int(generator_256.order())
        window = 10
        point = PointJacobi(
            curve_256, generator_256.x(), generator_256.y(), 1, order
        )
        multiplier = 0x1234567890ABCDEF
        digits = PointJacobi._fixed_digits(
            PointJacobi._canonical_scalar(multiplier, order),
            PointJacobi._fixed_digit_count(order, window),
            window,
        )

        self.assertEqual(len(digits), 26)
        self.assertEqual(1 << (window - 1), 512)

        coords = point._mul_fixed_digits(digits, window)
        product = PointJacobi(
            curve_256, coords[0], coords[1], coords[2], order
        )

        self.assertEqual(product, generator_256 * multiplier)

    def test_a_table_of_more_positions_than_an_interned_integer(self):
        """
        The most significant position is the one that advances no base.

        Every position but the last leaves the base of the next one behind it
        and the last does not, so a table of ``positions`` positions pays
        ``positions - 1`` of those advances and no more.  Where it stops is
        asserted for an order wide enough that the position counted up to is
        above the integers CPython keeps interned, which is what states that
        stopping follows a comparison of values.  A caller may hand any order
        to a point: `ecdsa.ecdsa.Private_key` takes any generator it is given.
        """
        order = (1 << 1027) + 1
        window = _MUL_WINDOW
        positions = PointJacobi._fixed_digit_count(order, window)
        entries = PointJacobi._fixed_table_length(order, window)
        point = PointJacobi(
            curve_256,
            generator_256.x(),
            generator_256.y(),
            1,
            order,
            True,
        )

        self.assertEqual((positions, entries), (258, 2064))
        self.assertGreater(positions, 256)

        with _CountedOperations(PointJacobi) as counted:
            point * 3
        table = point._PointJacobi__precompute

        self.assertEqual(len(table), entries)
        self.assertEqual(
            counted.counts(), (entries, (positions - 1) * window + 1)
        )

    @pytest.mark.skipif(not GMPY, reason="requires gmpy or gmpy2")
    def test_recoding_of_a_gmpy_multiplier(self):  # pragma: no cover
        # the recoding coerces its input, so that the digits do not depend on
        # which integer implementation the module found
        from .ellipticcurve import mpz

        order = int(generator_112r2.order())
        count = PointJacobi._fixed_digit_count(order, _MUL_WINDOW)
        canonical = PointJacobi._canonical_scalar(12345, order)

        self.assertEqual(
            PointJacobi._canonical_scalar(mpz(12345), mpz(order)), canonical
        )
        self.assertEqual(
            PointJacobi._fixed_digits(mpz(canonical), count, _MUL_WINDOW),
            PointJacobi._fixed_digits(canonical, count, _MUL_WINDOW),
        )


class TestEdwardsPrecompute(unittest.TestCase):
    """
    Tests of the twisted Edwards counterpart of the multiplication table.

    Both implementations share the recoding of `AbstractPoint` and build the
    same number of table entries, but two of their contracts differ and the
    ladders depend on the difference: an entry holds three values rather than
    two, and `PointEdwards._maybe_precompute()` returns the table while
    `PointJacobi._maybe_precompute()` returns nothing and leaves its caller to
    read the attribute.  Broader acceptance of this curve type is the job of
    `test_eddsa.py`.
    """

    def fresh_generator(self, generator_flag=True):
        """Return an Ed25519 generator whose table is not built yet."""
        generator = generator_ed25519
        prime = generator.curve().p()
        coord_x, coord_y = generator.x(), generator.y()
        return PointEdwards(
            generator.curve(),
            coord_x,
            coord_y,
            1,
            coord_x * coord_y % prime,
            generator.order(),
            generator_flag,
        )

    def test_precompute_table_is_empty_before_the_first_use(self):
        point = self.fresh_generator()

        self.assertIsInstance(point._PointEdwards__precompute, list)
        self.assertEqual(point._PointEdwards__precompute, [])

    def test_maybe_precompute_returns_the_table(self):
        point = self.fresh_generator()

        table = point._maybe_precompute()

        # `PointEdwards.__mul__()` tests the returned value, where
        # `PointJacobi.__mul__()` tests the attribute
        self.assertIs(table, point._PointEdwards__precompute)
        self.assertTrue(table)
        # built once, and the same list on every later call
        self.assertIs(point._maybe_precompute(), table)

    def test_maybe_precompute_of_a_non_generator_returns_an_empty_table(self):
        point = self.fresh_generator(False)

        self.assertEqual(point._maybe_precompute(), [])
        self.assertEqual(point._PointEdwards__precompute, [])

    def test_precompute_table_is_not_built_for_an_unusable_order(self):
        generator = generator_ed25519
        prime = generator.curve().p()
        # see the counterpart in `TestJacobi` for why twice the order is a
        # valid order to state and why the fixed length recoding refuses it
        order = 2 * int(generator.order())
        self.assertEqual(PointEdwards._fixed_ladder_usable(order), False)
        point = PointEdwards(
            generator.curve(),
            generator.x(),
            generator.y(),
            1,
            generator.x() * generator.y() % prime,
            order,
            True,
        )

        self.assertEqual(point._maybe_precompute(), [])
        self.assertEqual(point._PointEdwards__precompute, [])

        for multiplier in (0, 1, 2, 3, 12345, order - 1, order, order + 1):
            self.assertEqual(point * multiplier, generator * multiplier)
        self.assertEqual(point._PointEdwards__precompute, [])

    def test_precompute_table_shape(self):
        point = self.fresh_generator()
        digits, entries = _ladder_shape(point.order())
        prime = point.curve().p()

        table = point._maybe_precompute()

        self.assertEqual(len(table), entries)
        # three values per entry, the third one being the product of the two
        # affine coordinates that the addition formula of this curve type
        # consumes
        self.assertEqual(sorted(set(len(entry) for entry in table)), [3])
        for coord_x, coord_y, product in table:
            self.assertEqual(product, coord_x * coord_y % prime)

    def test_precompute_table_holds_the_odd_multiples_of_the_point(self):
        point = self.fresh_generator()
        plain = self.fresh_generator(False)
        digits, entries = _ladder_shape(point.order())
        window = _MUL_WINDOW

        table = point._maybe_precompute()

        offset = 0
        multiples = 1 << (window - 1)
        for position in range(digits):
            # the first, the second and the most significant position, which
            # between them cover the base of a position, the step within one
            # and the uniform width of the last one
            if position in (0, 1, digits - 1):
                for index in range(multiples):
                    expected = plain * ((2 * index + 1) << (position * window))
                    self.assertEqual(
                        table[offset + index][:2],
                        (expected.x(), expected.y()),
                    )
            offset += multiples
        self.assertEqual(offset, entries)

    def test_operation_count_with_a_precompute_table(self):
        point = self.fresh_generator()
        order = int(point.order())
        digits, _ = _ladder_shape(order)
        # the table is built by the first multiplication, not by the ones
        # being counted
        point._maybe_precompute()

        counts = []
        for multiplier in (2, order - 1, order, order + 1, 1 << 128):
            with _CountedOperations(PointEdwards) as counted:
                point * multiplier
            counts.append(counted.counts())

        # one addition per digit and no doubling at all, whatever the
        # multiplier was
        self.assertEqual(counts, [(digits, 0)] * len(counts))

    def test_operation_count_without_a_precompute_table(self):
        point = self.fresh_generator(False)
        order = int(point.order())
        digits, _ = _ladder_shape(order)

        counts = []
        for multiplier in (2, order - 1, order, order + 1, 1 << 128):
            with _CountedOperations(PointEdwards) as counted:
                point * multiplier
            counts.append(counted.counts())

        # the table of odd multiples of the point costs one doubling and
        # 2**(window-1) - 1 additions, then every digit costs one addition and
        # a whole window of doublings
        expected = (
            (1 << (_MUL_WINDOW - 1)) - 1 + digits,
            digits * _MUL_WINDOW + 1,
        )
        self.assertEqual(counts, [expected] * len(counts))
        self.assertEqual(point._PointEdwards__precompute, [])

    def test_operation_count_of_the_edge_multipliers(self):
        # `PointEdwards.__mul__()` normalises a multiplier before it chooses
        # any work from it, exactly as its Jacobi counterpart does, so zero,
        # one and the order cost what every other multiplier costs whether a
        # table has been built or not.  See the test of the same name in
        # `TestJacobi` on why answering them early would hide nothing.
        order = int(generator_ed25519.order())
        digits, _ = _ladder_shape(order)
        edges = (0, 1, 2, order - 1, order, order + 1)
        expected = {
            True: (digits, 0),
            False: (
                digits + (1 << (_MUL_WINDOW - 1)) - 1,
                digits * _MUL_WINDOW + 1,
            ),
        }

        for generator_flag in (True, False):
            point = self.fresh_generator(generator_flag)
            point._maybe_precompute()

            for multiplier in edges:
                with _CountedOperations(PointEdwards) as counted:
                    point * multiplier
                self.assertEqual(
                    counted.counts(), expected[generator_flag], generator_flag
                )

    def test_what_the_edge_multipliers_answer(self):
        # The results.  As on a Weierstrass curve, a multiplier of one is
        # answered with this very object once the ladder has done the work
        # every other multiplier pays for, and one more than the order with an
        # equal but distinct point.
        order = int(generator_ed25519.order())

        for generator_flag in (True, False):
            point = self.fresh_generator(generator_flag)
            point._maybe_precompute()

            self.assertEqual(point * 0, INFINITY)
            self.assertEqual(point * order, INFINITY)
            self.assertIs(point * 1, point)
            self.assertIs(point * True, point)
            self.assertEqual(point * (order + 1), point)
            self.assertIsNot(point * (order + 1), point)
            self.assertEqual(point * 2, point + point)
            self.assertEqual(point * (order - 1) + point, INFINITY)

    def test_multiplication_agrees_with_the_table_less_path(self):
        point = self.fresh_generator()
        plain = self.fresh_generator(False)
        order = int(point.order())

        for multiplier in (0, 1, 2, 3, order - 1, order, order + 1, 1 << 128):
            self.assertEqual(point * multiplier, plain * multiplier)

        self.assertTrue(point._PointEdwards__precompute)
        self.assertEqual(plain._PointEdwards__precompute, [])

    def test_pickle_carries_a_precompute_table_of_the_current_layout(self):
        """
        Round trip of a point of this class, table included.

        This class defines no `__getstate__`, here or in any release up to
        0.19.1, so the state is the plain instance dictionary and the
        multiplication table travels with it.  Only `__setstate__()` was added,
        and only to drop a table whose layout this code would not index; the
        Weierstrass counterpart of this test carries the reasoning, and
        `test_a_state_written_here_carries_a_table_of_this_layout` records the
        one direction that cannot be guarded.
        """
        point = self.fresh_generator()
        digits, entries = _ladder_shape(point.order())
        table = list(point._maybe_precompute())
        self.assertEqual(len(table), entries)

        # the state is the instance dictionary itself, this class adding no
        # writer of its own
        self.assertFalse("__getstate__" in PointEdwards.__dict__)
        self.assertEqual(
            sorted(point.__dict__.keys()),
            [
                "_PointEdwards__coords",
                "_PointEdwards__curve",
                "_PointEdwards__generator",
                "_PointEdwards__order",
                "_PointEdwards__precompute",
            ],
        )
        self.assertEqual(
            len(point.__dict__["_PointEdwards__precompute"]), entries
        )

        restored = pickle.loads(pickle.dumps(point))

        self.assertEqual(restored, point)
        # the table travelled and was recognised on the way in, entry for entry
        self.assertEqual(restored._PointEdwards__precompute, table)
        with _CountedOperations(PointEdwards) as counted:
            product = restored * 12345
        self.assertEqual(product, point * 12345)
        # so the first multiplication of the restored point costs what a
        # multiplication of the point it was made from costs: one addition per
        # digit and no doubling at all
        self.assertEqual(counted.counts(), (digits, 0))
        self.assertEqual(restored._PointEdwards__precompute, table)
        # and so does the next
        with _CountedOperations(PointEdwards) as counted:
            self.assertEqual(restored * 12345, product)
        self.assertEqual(counted.counts(), (digits, 0))

    def test_a_state_written_here_carries_a_table_of_this_layout(self):
        """
        The direction `__setstate__()` cannot guard, on this curve type.

        The Weierstrass counterpart of this test carries the reasoning.  What
        differs here is the contract on the other side: releases up to 0.19.1
        defined neither `__getstate__` nor `__setstate__` for this class, so
        they wrote and read the plain instance dictionary and built their table
        only while the attribute was false -- and this release still writes
        that same dictionary, so the table travels and such a release would
        index this layout as its own.  That residual is recorded in
        `SECURITY.md` as accepted; what is asserted here is that it is what it
        is said to be.
        """
        point = self.fresh_generator()
        _, entries = _ladder_shape(point.order())
        point._maybe_precompute()

        state = dict(point.__dict__)

        # the table is in the state, of this layout
        self.assertEqual(
            state["_PointEdwards__precompute"],
            point._PointEdwards__precompute,
        )
        self.assertEqual(len(state["_PointEdwards__precompute"]), entries)
        # what a release without a `__setstate__` for this class did on the way
        # in: the default, which is a bare update of the instance dictionary,
        # its own table build guarded on the attribute being false -- which it
        # is not, so it would index this one
        restored = PointEdwards.__new__(PointEdwards)
        restored.__dict__.update(state)

        self.assertTrue(restored._PointEdwards__precompute)
        self.assertEqual(restored, point)
        self.assertEqual(
            (restored.x(), restored.y()),
            (generator_ed25519.x(), generator_ed25519.y()),
        )
        self.assertEqual(
            restored._PointEdwards__order, generator_ed25519.order()
        )
        # the layout of the successive doubling ladder those releases indexed
        # is not this one, which is the whole of the residual: it held one
        # entry per bit of the order plus three, and its second entry was twice
        # the point where the second entry here is three times it
        self.assertNotEqual(bit_length(point.order()) + 3, entries)
        self.assertEqual(len(point._PointEdwards__precompute), entries)
        plain = self.fresh_generator(False)
        twice, thrice = plain * 2, plain * 3
        entry = point._PointEdwards__precompute[1]
        self.assertEqual((entry[0], entry[1]), (thrice.x(), thrice.y()))
        self.assertNotEqual((entry[0], entry[1]), (twice.x(), twice.y()))

    def test_setstate_discards_a_table_of_another_layout(self):
        point = self.fresh_generator()
        _, entries = _ladder_shape(point.order())
        # this class defines no `__getstate__`, so a state of it is the
        # instance dictionary
        template = dict(point.__dict__)

        for table in (
            # the layout of the successive doubling ladder
            [(1, 2, 2)] * (bit_length(point.order()) + 3),
            # a table long enough that using it instead of a rebuilt one would
            # compute a wrong point rather than run off the end of the list
            [(1, 2, 2)] * (entries + 4),
            [(1, 2, 2)] * (entries - 1),
            # the pairs of a Jacobi table rather than the triples of this one
            [(1, 2)] * entries,
            [],
            None,
            "junk",
        ):
            state = dict(template)
            state["_PointEdwards__precompute"] = table

            restored = PointEdwards.__new__(PointEdwards)
            restored.__setstate__(state)

            self.assertEqual(restored._PointEdwards__precompute, [])
            self.assertEqual(restored * 12345, generator_ed25519 * 12345)
            self.assertEqual(len(restored._PointEdwards__precompute), entries)

    def test_setstate_keeps_a_table_of_the_current_layout(self):
        point = self.fresh_generator()
        digits, entries = _ladder_shape(point.order())
        point._maybe_precompute()
        # this class defines no `__getstate__`, so a state of it is the
        # instance dictionary; the table is copied so that keeping it cannot be
        # confused with sharing the very list the warm point holds
        state = dict(point.__dict__)
        state["_PointEdwards__precompute"] = list(
            point._PointEdwards__precompute
        )
        self.assertEqual(len(state["_PointEdwards__precompute"]), entries)

        restored = PointEdwards.__new__(PointEdwards)
        restored.__setstate__(state)

        self.assertEqual(
            restored._PointEdwards__precompute,
            point._PointEdwards__precompute,
        )
        with _CountedOperations(PointEdwards) as counted:
            product = restored * 12345
        self.assertEqual(product, generator_ed25519 * 12345)
        self.assertEqual(counted.counts(), (digits, 0))

    def test_a_table_of_more_positions_than_an_interned_integer(self):
        """
        The counterpart of the same assertion on `PointJacobi`.

        This builder advances the base of the next position for every position
        but the most significant one too, so the same order states the same
        thing here: where the build stops follows a comparison of values, not
        of identities, for a position count above the integers CPython keeps
        interned.
        """
        generator = generator_ed25519
        prime = generator.curve().p()
        coord_x, coord_y = generator.x(), generator.y()
        order = (1 << 1027) + 1
        window = _MUL_WINDOW
        positions = PointEdwards._fixed_digit_count(order, window)
        entries = PointEdwards._fixed_table_length(order, window)
        point = PointEdwards(
            generator.curve(),
            coord_x,
            coord_y,
            1,
            coord_x * coord_y % prime,
            order,
            True,
        )

        self.assertEqual((positions, entries), (258, 2064))
        self.assertGreater(positions, 256)

        with _CountedOperations(PointEdwards) as counted:
            table = point._maybe_precompute()

        self.assertEqual(len(table), entries)
        self.assertEqual(
            counted.counts(),
            (entries - positions, (positions - 1) * window + 1),
        )
