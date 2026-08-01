import pytest

try:
    import unittest2 as unittest
except ImportError:
    import unittest
from hypothesis import given, settings
import hypothesis.strategies as st

try:
    from hypothesis import HealthCheck

    HC_PRESENT = True
except ImportError:  # pragma: no cover
    HC_PRESENT = False
from .numbertheory import inverse_mod
from ._compat import bit_length
from . import ellipticcurve
from .ellipticcurve import (
    CurveFp,
    INFINITY,
    Point,
    CurveEdTw,
    PointJacobi,
)


HYP_SETTINGS = {}
if HC_PRESENT:  # pragma: no branch
    HYP_SETTINGS["suppress_health_check"] = [HealthCheck.too_slow]
    HYP_SETTINGS["deadline"] = 5000


# NIST Curve P-192:
p = 6277101735386680763835789423207666416083908700390324961279
r = 6277101735386680763835789423176059013767194773182842284081
# s = 0x3045ae6fc8422f64ed579528d38120eae12196d5
# c = 0x3099d2bbbfcb2538542dcd5fb078b6ef5f3d6fe2c745de65
b = 0x64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1
Gx = 0x188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012
Gy = 0x07192B95FFC8DA78631011ED6B24CDD573F977A11E794811

c192 = CurveFp(p, -3, b)
p192 = Point(c192, Gx, Gy, r)

c_23 = CurveFp(23, 1, 1)
g_23 = Point(c_23, 13, 7, 7)


HYP_SLOW_SETTINGS = dict(HYP_SETTINGS)
HYP_SLOW_SETTINGS["max_examples"] = 2


@settings(**HYP_SLOW_SETTINGS)
@given(st.integers(min_value=1, max_value=r - 1))
def test_p192_mult_tests(multiple):
    inv_m = inverse_mod(multiple, r)

    p1 = p192 * multiple
    assert p1 * inv_m == p192


def add_n_times(point, n):
    ret = INFINITY
    i = 0
    while i <= n:
        yield ret
        ret = ret + point
        i += 1


# From X9.62 I.1 (p. 96):
@pytest.mark.parametrize(
    "p, m, check",
    [(g_23, n, exp) for n, exp in enumerate(add_n_times(g_23, 8))],
    ids=["g_23 test with mult {0}".format(i) for i in range(9)],
)
def test_add_and_mult_equivalence(p, m, check):
    assert p * m == check


# Repeated addition is the definition that multiplication has to agree with,
# and the order of ``g_23`` is small enough to walk a range three times as
# long as it: that covers every residue modulo the order, the multipliers in
# the range that are multiples of it -- 0, 7, 14 and 21 -- and the multipliers
# past it that no other test in this module reaches.  The comparison is of the
# coordinate pairs rather than of the points, which isolates the coordinates
# from everything else a point carries; ``Point.__eq__`` compares the curve as
# well, and these two points are on the same curve by construction.
@pytest.mark.parametrize(
    "p, m, check",
    [(g_23, n, exp) for n, exp in enumerate(add_n_times(g_23, 3 * 7))],
    ids=["g_23 wide test with mult {0}".format(i) for i in range(3 * 7 + 1)],
)
def test_add_and_mult_equivalence_past_order(p, m, check):
    product = p * m
    assert (product.x(), product.y()) == (check.x(), check.y())


class TestCurve(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.c_23 = CurveFp(23, 1, 1)

    def test_equality_curves(self):
        self.assertEqual(self.c_23, CurveFp(23, 1, 1))

    def test_inequality_curves(self):
        c192 = CurveFp(p, -3, b)
        self.assertNotEqual(self.c_23, c192)

    def test_inequality_curves_by_b_only(self):
        a = CurveFp(23, 1, 0)
        b = CurveFp(23, 1, 1)
        self.assertNotEqual(a, b)

    def test_usability_in_a_hashed_collection_curves(self):
        {self.c_23: None}

    def test_hashability_curves(self):
        hash(self.c_23)

    def test_conflation_curves(self):
        ne1, ne2, ne3 = CurveFp(24, 1, 1), CurveFp(23, 2, 1), CurveFp(23, 1, 2)
        eq1, eq2, eq3 = CurveFp(23, 1, 1), CurveFp(23, 1, 1), self.c_23
        self.assertEqual(len(set((c_23, eq1, eq2, eq3))), 1)
        self.assertEqual(len(set((c_23, ne1, ne2, ne3))), 4)
        self.assertDictEqual({c_23: None}, {eq1: None})
        self.assertIn(eq2, {eq3: None})

    def test___str__(self):
        self.assertEqual(str(self.c_23), "CurveFp(p=23, a=1, b=1)")

    def test___str___with_cofactor(self):
        c = CurveFp(23, 1, 1, 4)
        self.assertEqual(str(c), "CurveFp(p=23, a=1, b=1, h=4)")


class TestCurveEdTw(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.c_23 = CurveEdTw(23, 1, 1)

    def test___str__(self):
        self.assertEqual(str(self.c_23), "CurveEdTw(p=23, a=1, d=1)")

    def test___str___with_cofactor(self):
        c = CurveEdTw(23, 1, 1, 4)
        self.assertEqual(str(c), "CurveEdTw(p=23, a=1, d=1, h=4)")

    def test_usability_in_a_hashed_collection_curves(self):
        {self.c_23: None}

    def test_hashability_curves(self):
        hash(self.c_23)


class TestPoint(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.c_23 = CurveFp(23, 1, 1)
        cls.g_23 = Point(cls.c_23, 13, 7, 7)

        p = 6277101735386680763835789423207666416083908700390324961279
        r = 6277101735386680763835789423176059013767194773182842284081
        # s = 0x3045ae6fc8422f64ed579528d38120eae12196d5
        # c = 0x3099d2bbbfcb2538542dcd5fb078b6ef5f3d6fe2c745de65
        b = 0x64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1
        Gx = 0x188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012
        Gy = 0x07192B95FFC8DA78631011ED6B24CDD573F977A11E794811

        cls.c192 = CurveFp(p, -3, b)
        cls.p192 = Point(cls.c192, Gx, Gy, r)

    def test_p192(self):
        # Checking against some sample computations presented
        # in X9.62:
        d = 651056770906015076056810763456358567190100156695615665659
        Q = d * self.p192
        self.assertEqual(
            Q.x(), 0x62B12D60690CDCF330BABAB6E69763B471F994DD702D16A5
        )

        k = 6140507067065001063065065565667405560006161556565665656654
        R = k * self.p192
        self.assertEqual(
            R.x(), 0x885052380FF147B734C330C43D39B2C4A89F29B0F749FEAD
        )
        self.assertEqual(
            R.y(), 0x9CF9FA1CBEFEFB917747A3BB29C072B9289C2547884FD835
        )

        u1 = 2563697409189434185194736134579731015366492496392189760599
        u2 = 6266643813348617967186477710235785849136406323338782220568
        temp = u1 * self.p192 + u2 * Q
        self.assertEqual(
            temp.x(), 0x885052380FF147B734C330C43D39B2C4A89F29B0F749FEAD
        )
        self.assertEqual(
            temp.y(), 0x9CF9FA1CBEFEFB917747A3BB29C072B9289C2547884FD835
        )

    def test_double_infinity(self):
        p1 = INFINITY
        p3 = p1.double()
        self.assertEqual(p1, p3)
        self.assertEqual(p3.x(), p1.x())
        self.assertEqual(p3.y(), p3.y())

    def test_double(self):
        x1, y1, x3, y3 = (3, 10, 7, 12)

        p1 = Point(self.c_23, x1, y1)
        p3 = p1.double()
        self.assertEqual(p3.x(), x3)
        self.assertEqual(p3.y(), y3)

    def test_double_to_infinity(self):
        p1 = Point(self.c_23, 11, 20)
        p2 = p1.double()
        self.assertEqual((p2.x(), p2.y()), (4, 0))
        self.assertNotEqual(p2, INFINITY)
        p3 = p2.double()
        self.assertEqual(p3, INFINITY)
        self.assertIs(p3, INFINITY)

    def test_add_self_to_infinity(self):
        p1 = Point(self.c_23, 11, 20)
        p2 = p1 + p1
        self.assertEqual((p2.x(), p2.y()), (4, 0))
        self.assertNotEqual(p2, INFINITY)
        p3 = p2 + p2
        self.assertEqual(p3, INFINITY)
        self.assertIs(p3, INFINITY)

    def test_mul_to_infinity(self):
        p1 = Point(self.c_23, 11, 20)
        p2 = p1 * 2
        self.assertEqual((p2.x(), p2.y()), (4, 0))
        self.assertNotEqual(p2, INFINITY)
        p3 = p2 * 2
        self.assertEqual(p3, INFINITY)
        self.assertIs(p3, INFINITY)

    def test_multiply(self):
        x1, y1, m, x3, y3 = (3, 10, 2, 7, 12)
        p1 = Point(self.c_23, x1, y1)
        p3 = p1 * m
        self.assertEqual(p3.x(), x3)
        self.assertEqual(p3.y(), y3)

    # Trivial tests from X9.62 B.3:
    def test_add(self):
        """We expect that on curve c, (x1,y1) + (x2, y2 ) = (x3, y3)."""

        x1, y1, x2, y2, x3, y3 = (3, 10, 9, 7, 17, 20)
        p1 = Point(self.c_23, x1, y1)
        p2 = Point(self.c_23, x2, y2)
        p3 = p1 + p2
        self.assertEqual(p3.x(), x3)
        self.assertEqual(p3.y(), y3)

    def test_add_as_double(self):
        """We expect that on curve c, (x1,y1) + (x2, y2 ) = (x3, y3)."""

        x1, y1, x2, y2, x3, y3 = (3, 10, 3, 10, 7, 12)
        p1 = Point(self.c_23, x1, y1)
        p2 = Point(self.c_23, x2, y2)
        p3 = p1 + p2
        self.assertEqual(p3.x(), x3)
        self.assertEqual(p3.y(), y3)

    def test_equality_points(self):
        self.assertEqual(self.g_23, Point(self.c_23, 13, 7, 7))

    def test_inequality_points(self):
        c = CurveFp(100, -3, 100)
        p = Point(c, 100, 100, 100)
        self.assertNotEqual(self.g_23, p)

    def test_inequality_points_diff_types(self):
        c = CurveFp(100, -3, 100)
        self.assertNotEqual(self.g_23, c)

    def test_inequality_diff_y(self):
        p1 = Point(self.c_23, 6, 4)
        p2 = Point(self.c_23, 6, 19)

        self.assertNotEqual(p1, p2)

    def test_to_bytes_from_bytes(self):
        p = Point(self.c_23, 3, 10)

        self.assertEqual(p, Point.from_bytes(self.c_23, p.to_bytes()))

    def test_add_to_neg_self(self):
        p = Point(self.c_23, 3, 10)

        self.assertEqual(INFINITY, p + (-p))

    def test_add_to_infinity(self):
        p = Point(self.c_23, 3, 10)

        self.assertIs(p, p + INFINITY)

    def test_mul_infinity_by_scalar(self):
        self.assertIs(INFINITY, INFINITY * 10)

    def test_mul_by_negative(self):
        p = Point(self.c_23, 3, 10)

        self.assertEqual(p * -5, (-p) * 5)

    def test_str_infinity(self):
        self.assertEqual(str(INFINITY), "infinity")

    def test_str_point(self):
        p = Point(self.c_23, 3, 10)

        self.assertEqual(str(p), "(3,10)")

    # Multiplication of an affine point answers the point at infinity itself on
    # a path of its own and then splits in two: it hands the work to the Jacobi
    # coordinate implementation for the orders a multiplier can be normalised
    # against, with nothing at all answered ahead of that hand-off, and keeps
    # the signed digit ladder for every other point -- which is the one
    # ``g_23`` with its order of 7 and any point constructed without an order
    # take, together with the shortcuts for a multiplier of zero, of one, of a
    # multiple of the order and of a negative value that only that ladder still
    # needs.  The tests from here on pin down each of those paths against
    # coordinates derived by repeated addition, and pin down the identity of
    # the point at infinity wherever the shared instance is what comes back.

    def test_mul_by_zero_with_order(self):
        self.assertIs(self.g_23 * 0, INFINITY)
        self.assertIs(self.p192 * 0, INFINITY)

    def test_mul_by_one_with_order(self):
        # the ladder for the small order, the delegation for the large one,
        # and both have to answer with this very object -- the delegation after
        # it has done the work every other multiplier pays for, see
        # `PointJacobi.__mul__()`.
        #
        # Handing back the multiplied object itself is what the X9.62 D.3.2
        # ladder of every release up to 0.19.1 did for this multiplier: its
        # loop bound leaves the accumulator at the `result = self` it was
        # initialised with, so the object that comes back is the object that
        # went in.  That ladder is still in this module and still does it,
        # which `test_mul_by_one_without_order` below measures on the one path
        # that reaches it, so an implementation that answered this multiplier
        # with an equal but distinct point would be a change a caller can see.
        small = self.g_23 * 1
        self.assertEqual((small.x(), small.y()), (13, 7))
        large = self.p192 * 1
        self.assertEqual((large.x(), large.y()), (Gx, Gy))
        self.assertIs(small, self.g_23)
        self.assertIs(large, self.p192)

    def test_mul_by_one_keeps_the_order_the_point_knows(self):
        # A separate claim from the one above, and kept in a method of its own
        # rather than folded into it: the product of this multiplier is the
        # multiplied object itself, so it reports the order that object was
        # built with, which a point built from coordinates alone would not
        # carry.  What it guards is that neither the shortcut nor the
        # delegation hands back a copy that has lost the order -- a point
        # without one takes a different ladder, so losing it here would move
        # the work every later multiplication of that product does.
        small = self.g_23 * 1
        large = self.p192 * 1

        self.assertEqual(small.order(), 7)
        self.assertEqual(large.order(), r)

    def test_mul_by_one_without_order(self):
        # a point that knows no order keeps the shortcut as well
        point = Point(self.c_23, 3, 10)

        self.assertIs(point * 1, point)

    def test_mul_by_order_minus_one(self):
        small = self.g_23 * (7 - 1)
        self.assertEqual((small.x(), small.y()), (13, 16))
        large = self.p192 * (r - 1)
        self.assertEqual((large.x(), large.y()), (Gx, p - Gy))

    def test_mul_by_order(self):
        self.assertIs(self.g_23 * 7, INFINITY)
        self.assertIs(self.p192 * r, INFINITY)

    def test_mul_by_order_plus_one(self):
        small = self.g_23 * (7 + 1)
        self.assertEqual((small.x(), small.y()), (13, 7))
        large = self.p192 * (r + 1)
        self.assertEqual((large.x(), large.y()), (Gx, Gy))

    def test_mul_by_twice_order(self):
        self.assertIs(self.g_23 * (2 * 7), INFINITY)
        self.assertIs(self.p192 * (2 * r), INFINITY)

    def test_mul_by_more_than_order(self):
        small = self.g_23 * (2 * 7 + 3)
        self.assertEqual((small.x(), small.y()), (17, 3))
        large = self.p192 * (2 * r + 2)
        self.assertEqual(
            (large.x(), large.y()),
            (
                0xDAFEBF5828783F2AD35534631588A3F629A70FB16982A888,
                0xDD6BDA0D993DA0FA46B27BBC141B868F59331AFA5C7E93AB,
            ),
        )

    def test_mul_without_order_small_multiplier(self):
        # A point constructed without an order has nothing to normalise a
        # multiplier against, so it keeps the ladder whatever its curve.
        # Three is the smallest multiplier whose signed digit recoding holds a
        # negative, a zero and a positive digit, so all three cases of the
        # ladder body run for it.
        point = Point(self.c_23, 3, 10)
        product = point * 3
        self.assertEqual((product.x(), product.y()), (19, 5))

    def test_mul_without_order_multiplier_over_point_order(self):
        # (3,10) has order 28 on this curve, but the point is not told so and
        # the multiplication may not assume it
        point = Point(self.c_23, 3, 10)
        self.assertIs(point * 28, INFINITY)
        wrapped = point * 29
        self.assertEqual((wrapped.x(), wrapped.y()), (3, 10))

    def test_mul_without_order_large_multiplier(self):
        # wide enough that the ladder runs for tens of iterations, which the
        # toy curve cannot ask of it
        point = Point(self.c192, Gx, Gy)
        product = point * 0xDEADBEEF12345678
        self.assertEqual(
            (product.x(), product.y()),
            (
                0x82FC626A66CB9AD3F319499240D3E2E2FC2209A1C86FAD91,
                0xF3C107C467F55C5FA4CDDD43FE9618B3680604A0F955DF6A,
            ),
        )

    def test_mul_without_order_matches_repeated_addition(self):
        # (3,10) has order 28 on this curve, so a range this long wraps it and
        # covers the multiplier that annihilates the point together with the
        # ones on either side of it
        point = Point(self.c_23, 3, 10)
        for multiplier, expected in enumerate(add_n_times(point, 30)):
            product = point * multiplier
            self.assertEqual(
                (product.x(), product.y()), (expected.x(), expected.y())
            )

    def test_mul_with_even_order(self):
        # An even order cannot be used to normalise a multiplier, because the
        # normalisation makes the multiplier odd by adding the order to it, so
        # such a point keeps the ladder as well.  28 is the true order of
        # (3,10) here, which is what lets the point be constructed with it.
        point = Point(self.c_23, 3, 10, 28)
        product = point * 5
        self.assertEqual((product.x(), product.y()), (9, 16))
        self.assertIs(point * 28, INFINITY)

    def test_mul_by_multiple_of_true_order_below_given_order(self):
        # A point handed an order that is a multiple of its true one, 77 for a
        # point of order 7 here, makes a multiplier that annihilates the point
        # without being a multiple of the order the point knows: 7 is not a
        # multiple of 77, so the multiplication cannot tell from the order
        # alone that the answer is the point at infinity, and has to recognise
        # it in the result it computed.  Nothing in this library constructs
        # such a point -- an order that is not the true one is documented as
        # unsupported -- but the multiplication has to stay correct for it.
        point = Point(self.c_23, 13, 7, 77)
        self.assertIs(point * 7, INFINITY)

    def test_mul_by_negative_with_order(self):
        small = self.g_23 * -1
        self.assertEqual((small.x(), small.y()), (13, 16))
        large = self.p192 * -7
        self.assertEqual(
            (large.x(), large.y()),
            (
                0x8DA75A1F75DDCD7660F923243060EDCE5DE37F007011FCFD,
                0xA834A030979F4CABE7DBF247024C3FE12B48FD069BF6004A,
            ),
        )

    def test_mul_by_negative_without_order(self):
        point = Point(self.c_23, 3, 10)
        product = point * -5
        self.assertEqual((product.x(), product.y()), (9, 7))

    def test_mul_by_negative_multiple_of_order(self):
        # the ladder recognises such a multiplier from the order before it
        # deals with the sign; the delegation recognises it from the point it
        # computed, having normalised the multiplier first
        self.assertIs(self.g_23 * -7, INFINITY)
        self.assertIs(self.p192 * -r, INFINITY)

    def test_mul_infinity_by_large_scalar(self):
        self.assertIs(INFINITY * 0xDEADBEEF12345678, INFINITY)

    def test_mul_infinity_by_negative_scalar(self):
        self.assertIs(INFINITY * -10, INFINITY)

    def test_rmul_with_order(self):
        self.assertIs(0 * self.g_23, INFINITY)
        self.assertIs(7 * self.g_23, INFINITY)
        product = 3 * self.g_23
        self.assertEqual((product.x(), product.y()), (17, 3))
        product = -3 * self.g_23
        self.assertEqual((product.x(), product.y()), (17, 20))
        product = (r + 1) * self.p192
        self.assertEqual((product.x(), product.y()), (Gx, Gy))

    def test_rmul_without_order(self):
        point = Point(self.c_23, 3, 10)
        for multiplier, expected in enumerate(add_n_times(point, 8)):
            product = multiplier * point
            self.assertEqual(
                (product.x(), product.y()), (expected.x(), expected.y())
            )


def count_jacobi_operations(work):
    """
    Count the point additions and doublings in Jacobi coordinates a call makes.

    The two methods every ladder of `PointJacobi` dispatches its arithmetic
    through are replaced by counting wrappers for the duration of the call and
    restored in a `finally`, so that no later test and no other caller in the
    process ever sees a patched class.  Wrapping only the two dispatchers, and
    passing their arguments straight on, keeps the count independent of which
    formula a ladder ends up choosing.

    :param callable work: called once, with no arguments

    :return: what `work` returned, the number of additions and the number of
        doublings
    :rtype: tuple of object, int, int
    """
    original_add = PointJacobi.__dict__["_add"]
    original_double = PointJacobi.__dict__["_double"]
    counted = [0, 0]

    def counting_add(*args, **kwargs):
        counted[0] += 1
        return original_add(*args, **kwargs)

    def counting_double(*args, **kwargs):
        counted[1] += 1
        return original_double(*args, **kwargs)

    PointJacobi._add = counting_add
    PointJacobi._double = counting_double
    try:
        result = work()
    finally:
        PointJacobi._add = original_add
        PointJacobi._double = original_double
    return result, counted[0], counted[1]


class TestAffineMultiplicationCost(unittest.TestCase):
    """
    What the delegation of the affine multiplication is worth.

    The tests above assert the coordinates the affine multiplication computes,
    which the ladder it replaced computed just as correctly; none of them would
    notice a point whose order can be used going back to that ladder.  What
    made the ladder unusable for a secret multiplier is that the number of
    point operations it performed followed the multiplier -- one iteration per
    bit of it, and one addition per non-zero digit of its signed recoding -- so
    the number of operations is what has to be asserted here, and asserted as
    an exact value rather than as a bound (CVE-2024-23342).

    The operations counted are the ones performed in Jacobi coordinates, which
    is what makes these tests state both halves of the claim at once: an
    ordered point performs a fixed number of them because it hands the work
    over, and a point whose order cannot be used performs none at all because
    it keeps the ladder in affine coordinates.
    """

    @classmethod
    def setUpClass(cls):
        cls.c_23 = CurveFp(23, 1, 1)
        cls.g_23 = Point(cls.c_23, 13, 7, 7)
        cls.c192 = c192
        cls.p192 = Point(c192, Gx, Gy, r)

    # An arbitrary constant wider than the order of P-192, used to fill the
    # bits below the top one of every multiplier these tests use.  Nothing
    # depends on its value, only on the bit width of what is built from it, and
    # taking it from here rather than from a random source is what makes every
    # count below reproducible on every interpreter.
    FILL = 0x9E3779B97F4A7C15F39CC0605CEDC8341082276BF3A27251F86C6A11D0C18E95

    def multipliers_of_every_width(self, top):
        """
        One multiplier of each of several bit widths, `top` bits and down.

        The widths are spread across the whole range a multiplier of a point on
        this curve can occupy, because a ladder whose cost follows the
        multiplier costs visibly less for the narrow ones; `top` has to be wide
        enough that `top // 4` is still at least two bits.
        """
        multipliers = []
        for width in (top, top - 16, top - 32, top // 2, top // 4, 8, 2):
            value = (1 << (width - 1)) | (self.FILL % (1 << (width - 1)))
            assert bit_length(value) == width
            multipliers.append(value)
        return multipliers

    def expected_delegated_shape(self, order):
        """
        Additions and doublings the delegation performs, from the order alone.

        The point handed over is not a curve generator, so it builds no
        multiplication table and takes the ladder that works without one: one
        addition per digit of the recoding of the multiplier, plus the ones
        that build the odd multiples of the point, and a whole window of
        doublings per digit but the most significant, plus the one that steps
        between consecutive odd multiples.
        """
        window = ellipticcurve._MUL_WINDOW
        digits = PointJacobi._fixed_digit_count(order, window)
        return digits + (1 << (window - 1)) - 1, (digits - 1) * window + 1

    def test_the_order_of_p192_gives_the_shape_asserted_below(self):
        """
        The literal count, so that these tests bring a number with them.

        The order of P-192 is 192 bits wide, which at the window this module is
        built with makes 49 digits, 56 additions and 193 doublings.
        """
        self.assertEqual(bit_length(r), 192)
        self.assertEqual(ellipticcurve._MUL_WINDOW, 4)
        self.assertEqual(PointJacobi._fixed_digit_count(r, 4), 49)
        self.assertEqual(self.expected_delegated_shape(r), (56, 193))

    def test_an_ordered_point_costs_the_same_for_every_multiplier(self):
        """
        Every multiplier of every width, and the edges, cost one exact amount.

        Zero and the multiples of the order are included: the delegation reads
        the point at infinity off the point it computed instead of answering
        those multipliers before doing the work, so they cost what the rest
        cost.
        """
        expected = self.expected_delegated_shape(r)
        counts = set()
        multipliers = self.multipliers_of_every_width(192)
        multipliers.extend([0, 1, 2, r - 1, r, r + 1, 2 * r, 2 * r + 3])
        for multiplier in multipliers:
            _, additions, doublings = count_jacobi_operations(
                lambda value=multiplier: self.p192 * value
            )
            counts.add((additions, doublings))
        self.assertEqual(sorted(counts), [expected])

    def test_the_delegated_product_is_the_point_the_ladder_computes(self):
        """
        The count above belongs to work that arrives at the right point.

        Asserted against the ladder itself, reached through a point built with
        the same coordinates and no order, so that the two implementations are
        compared on the same inputs.
        """
        order_less = Point(self.c192, Gx, Gy)
        for multiplier in self.multipliers_of_every_width(192) + [1, 2, r - 1]:
            delegated = self.p192 * multiplier
            laddered = order_less * multiplier
            self.assertEqual(
                (delegated.x(), delegated.y()),
                (laddered.x(), laddered.y()),
            )

    def test_a_point_that_knows_no_order_keeps_the_affine_ladder(self):
        """
        No operation in Jacobi coordinates at all, so nothing was handed over.

        This is the other half of the claim: the delegation is what the count
        above measures, and a point that cannot use its order does not reach
        it.  The number of point operations that ladder performs follows the
        multiplier, so it is not side channel hardened; it is kept as it is
        because a point without an order still has to multiply, and a caller
        who builds one through the public constructors of this module and
        multiplies it gets that unhardened ladder.  What the countermeasure
        rests on is narrower: every curve this library registers declares an
        order the recoding can use, and `ecdsa.ecdsa.Public_key` attaches it
        to the public points that arrive without one, so no route through the
        signing, key generation and ECDH paths of this library multiplies a
        point without a usable order by a secret.
        """
        order_less = Point(self.c192, Gx, Gy)
        for multiplier in (1, 2, 0xDEADBEEF12345678):
            _, additions, doublings = count_jacobi_operations(
                lambda value=multiplier: order_less * value
            )
            self.assertEqual((additions, doublings), (0, 0))

    def test_an_order_the_recoding_cannot_use_keeps_the_affine_ladder(self):
        """
        The two shapes of order that cannot normalise a multiplier.

        Seven is odd but narrower than a single window, and twenty-eight is
        even, which the normalisation cannot work with because it makes the
        multiplier odd by adding the order to it.  Both are orders of points on
        the curve of 23 points, and a caller who builds a point with an order
        of either shape and multiplies it by a value of their own gets the
        affine ladder, whose number of point operations follows that value.
        What holds is narrower: no route through the curves this library
        registers and its own high level entry points arrives at an order of
        either shape with a secret, because every registered curve declares an
        order that is both odd and wide enough.
        """
        even_order = Point(self.c_23, 3, 10, 28)
        for point in (self.g_23, even_order):
            for multiplier in (1, 3, 5):
                _, additions, doublings = count_jacobi_operations(
                    lambda value=multiplier, p=point: p * value
                )
                self.assertEqual((additions, doublings), (0, 0))

    def test_a_negative_multiplier_costs_what_every_other_one_costs(self):
        """
        The sign of the multiplier is not answered ahead of the delegation.

        Answering a negative multiplier as `(-self) * (-e)` would have handed
        the work to the affine ladder, because the negation of a point carries
        no order, and that ladder performs a number of point operations that
        follows the multiplier.  The delegation is reached first instead, so a
        negative multiplier is normalised into the same width as every other
        one and costs the same exact amount -- and the product is still the
        negation of the product of its absolute value.
        """
        expected = self.expected_delegated_shape(r)
        _, additions, doublings = count_jacobi_operations(
            lambda: self.p192 * -5
        )
        self.assertEqual((additions, doublings), expected)
        self.assertEqual(self.p192 * -5, (-self.p192) * 5)
        self.assertEqual(self.p192 * -5, -(self.p192 * 5))

    def test_the_counting_wrappers_are_removed_afterwards(self):
        """A wrapper left behind would be seen by every later test."""
        original_add = PointJacobi.__dict__["_add"]
        original_double = PointJacobi.__dict__["_double"]

        count_jacobi_operations(lambda: None)
        self.assertIs(PointJacobi.__dict__["_add"], original_add)
        self.assertIs(PointJacobi.__dict__["_double"], original_double)

        def explode():
            raise ValueError("measured work failed")

        self.assertRaises(ValueError, count_jacobi_operations, explode)
        self.assertIs(PointJacobi.__dict__["_add"], original_add)
        self.assertIs(PointJacobi.__dict__["_double"], original_double)
