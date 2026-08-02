#! /usr/bin/env python
# -*- coding: utf-8 -*-
#
# Implementation of elliptic curves, for cryptographic applications.
#
# This module doesn't provide any way to choose a random elliptic
# curve, nor to verify that an elliptic curve was chosen randomly,
# because one can simply use NIST's standard curves.
#
# Notes from X9.62-1998 (draft):
#   Nomenclature:
#     - Q is a public key.
#     The "Elliptic Curve Domain Parameters" include:
#     - q is the "field size", which in our case equals p.
#     - p is a big prime.
#     - G is a point of prime order (5.1.1.1).
#     - n is the order of G (5.1.1.1).
#   Public-key validation (5.2.2):
#     - Verify that Q is not the point at infinity.
#     - Verify that X_Q and Y_Q are in [0,p-1].
#     - Verify that Q is on the curve.
#     - Verify that nQ is the point at infinity.
#   Signature generation (5.3):
#     - Pick random k from [1,n-1].
#   Signature checking (5.4.2):
#     - Verify that r and s are in [1,n-1].
#
# Revision history:
#    2005.12.31 - Initial version.
#    2008.11.25 - Change CurveFp.is_on to contains_point.
#
# Written in 2005 by Peter Pearson and placed in the public domain.
# Modified extensively as part of python-ecdsa.

from __future__ import division

import operator

try:
    from gmpy2 import mpz

    GMPY = True
except ImportError:  # pragma: no branch
    try:
        from gmpy import mpz

        GMPY = True
    except ImportError:
        GMPY = False


from six import python_2_unicode_compatible
from . import numbertheory
from ._compat import normalise_bytes, int_to_bytes, bit_length, bytes_to_int
from .errors import MalformedPointError
from .util import orderlen, string_to_number, number_to_string


# Nonce bit-length hardening, CVE-2024-23342 / GHSA-wj6h-64fc-37mp, OWASP ASVS
# 4.0 requirement 6.2.8.  Where the order of a point can be used, see
# `AbstractPoint._fixed_ladder_usable()`, a multiplier is replaced by
# `AbstractPoint._canonical_scalar()` with a congruent odd value between the
# order and three times it, then recoded by `AbstractPoint._fixed_digits()`
# into a fixed length sequence of non-zero digits.  The digit count comes from
# the public order and no digit is skipped, so the point additions and
# doublings a ladder SCHEDULES follow that order alone -- for a generator once
# its precomputation table is built.  Nothing is answered ahead of the recoding
# either: a shortcut for zero, one, a multiple of the order or a negative
# multiplier is the very short circuit CVE-2024-23342 is about, and signing,
# key generation and ECDH all accept a secret of one.  Those multipliers still
# get back what they always did, down to object identity, picked out by index
# after the ladder has run.
#
# Two things are deliberately not claimed, and `SECURITY.md` records both: the
# canonical multiplier takes one of three widths rather than a constant one,
# and the at most two residues of any order that end a ladder with its
# accumulator equal to the entry being added cost a twisted Edwards ladder one
# doubling more than the schedule.  Per-operation cost varies too, integer
# arithmetic costing according to operand limb width and the reduction modulo
# the field prime being skipped where that is faster (see
# `PointJacobi._double_with_z_1()`).
#
# A point in Jacobi coordinates that reports no order is recoded all the same,
# against its curve: Hasse's theorem bounds every order such a point can
# have, so `AbstractPoint._curve_scalar_width()` gives a width where the order
# cannot, and `PointJacobi._mul_curve_fixed()` performs a fixed number of point
# operations for every multiplier that curve can hold.  That is the path an
# ECDH exchange takes against a remote public point decoded from an encoding --
# no encoding carries one -- where the multiplier is the long term private key.
#
# What keeps the multiplier driven ladder of releases up to 0.19.1 is a point
# whose order the recoding cannot use (none of the registered curves), a
# multiplier no group of the point's curve could hold, a negative multiplier of
# a point that reports no order, an affine point without a usable order, and
# `PointJacobi.mul_add()`, used for verification with public multipliers.  No
# secret of this library reaches any of them: signing, key generation and EdDSA
# multiply a generator that carries its order, `ecdsa.ecdsa.Public_key` refuses
# a generator that declares none, and a private key and a nonce are both drawn
# from `[1, order)`.  `SECURITY.md` records each case.
#
# Width in bits of the recoded digits, and so of the odd multiples a table
# holds per digit position: wider means fewer additions against a larger table.
# It is the only width the recoding uses; an order too narrow to carry it stays
# on the multiplier driven ladder, see `AbstractPoint._fixed_window()`.
_MUL_WINDOW = 4


@python_2_unicode_compatible
class CurveFp(object):
    """
    :term:`Short Weierstrass Elliptic Curve <short Weierstrass curve>` over a
    prime field.
    """

    if GMPY:  # pragma: no branch

        def __init__(self, p, a, b, h=None):
            """
            The curve of points satisfying y^2 = x^3 + a*x + b (mod p).

            h is an integer that is the cofactor of the elliptic curve domain
            parameters; it is the number of points satisfying the elliptic
            curve equation divided by the order of the base point. It is used
            for selection of efficient algorithm for public point verification.
            """
            self.__p = mpz(p)
            self.__a = mpz(a)
            self.__b = mpz(b)
            # h is not used in calculations and it can be None, so don't use
            # gmpy with it
            self.__h = h

    else:  # pragma: no branch

        def __init__(self, p, a, b, h=None):
            """
            The curve of points satisfying y^2 = x^3 + a*x + b (mod p).

            h is an integer that is the cofactor of the elliptic curve domain
            parameters; it is the number of points satisfying the elliptic
            curve equation divided by the order of the base point. It is used
            for selection of efficient algorithm for public point verification.
            """
            self.__p = p
            self.__a = a
            self.__b = b
            self.__h = h

    def __eq__(self, other):
        """Return True if other is an identical curve, False otherwise.

        Note: the value of the cofactor of the curve is not taken into account
        when comparing curves, as it's derived from the base point and
        intrinsic curve characteristic (but it's complex to compute),
        only the prime and curve parameters are considered.
        """
        if isinstance(other, CurveFp):
            p = self.__p
            return (
                self.__p == other.__p
                and self.__a % p == other.__a % p
                and self.__b % p == other.__b % p
            )
        return NotImplemented

    def __ne__(self, other):
        """Return False if other is an identical curve, True otherwise."""
        return not self == other

    def __hash__(self):
        return hash((self.__p, self.__a, self.__b))

    def p(self):
        return self.__p

    def a(self):
        return self.__a

    def b(self):
        return self.__b

    def cofactor(self):
        return self.__h

    def contains_point(self, x, y):
        """Is the point (x,y) on this curve?"""
        return (y * y - ((x * x + self.__a) * x + self.__b)) % self.__p == 0

    def __str__(self):
        if self.__h is not None:
            return "CurveFp(p={0}, a={1}, b={2}, h={3})".format(
                self.__p,
                self.__a,
                self.__b,
                self.__h,
            )
        return "CurveFp(p={0}, a={1}, b={2})".format(
            self.__p,
            self.__a,
            self.__b,
        )


class CurveEdTw(object):
    """Parameters for a Twisted Edwards Elliptic Curve"""

    if GMPY:  # pragma: no branch

        def __init__(self, p, a, d, h=None, hash_func=None):
            """
            The curve of points satisfying a*x^2 + y^2 = 1 + d*x^2*y^2 (mod p).

            h is the cofactor of the curve.
            hash_func is the hash function associated with the curve
             (like SHA-512 for Ed25519)
            """
            self.__p = mpz(p)
            self.__a = mpz(a)
            self.__d = mpz(d)
            self.__h = h
            self.__hash_func = hash_func

    else:

        def __init__(self, p, a, d, h=None, hash_func=None):
            """
            The curve of points satisfying a*x^2 + y^2 = 1 + d*x^2*y^2 (mod p).

            h is the cofactor of the curve.
            hash_func is the hash function associated with the curve
             (like SHA-512 for Ed25519)
            """
            self.__p = p
            self.__a = a
            self.__d = d
            self.__h = h
            self.__hash_func = hash_func

    def __eq__(self, other):
        """Returns True if other is an identical curve."""
        if isinstance(other, CurveEdTw):
            p = self.__p
            return (
                self.__p == other.__p
                and self.__a % p == other.__a % p
                and self.__d % p == other.__d % p
            )
        return NotImplemented

    def __ne__(self, other):
        """Return False if the other is an identical curve, True otherwise."""
        return not self == other

    def __hash__(self):
        return hash((self.__p, self.__a, self.__d))

    def contains_point(self, x, y):
        """Is the point (x, y) on this curve?"""
        return (
            self.__a * x * x + y * y - 1 - self.__d * x * x * y * y
        ) % self.__p == 0

    def p(self):
        return self.__p

    def a(self):
        return self.__a

    def d(self):
        return self.__d

    def hash_func(self, data):
        return self.__hash_func(data)

    def cofactor(self):
        return self.__h

    def __str__(self):
        if self.__h is not None:
            return "CurveEdTw(p={0}, a={1}, d={2}, h={3})".format(
                self.__p,
                self.__a,
                self.__d,
                self.__h,
            )
        return "CurveEdTw(p={0}, a={1}, d={2})".format(
            self.__p,
            self.__a,
            self.__d,
        )


class AbstractPoint(object):
    """Class for common methods of elliptic curve points."""

    @staticmethod
    def _from_raw_encoding(data, raw_encoding_length):
        """
        Decode public point from :term:`raw encoding`.

        :term:`raw encoding` is the same as the :term:`uncompressed` encoding,
        but without the 0x04 byte at the beginning.
        """
        # real assert, from_bytes() should not call us with different length
        assert len(data) == raw_encoding_length
        xs = data[: raw_encoding_length // 2]
        ys = data[raw_encoding_length // 2 :]
        # real assert, raw_encoding_length is calculated by multiplying an
        # integer by two so it will always be even
        assert len(xs) == raw_encoding_length // 2
        assert len(ys) == raw_encoding_length // 2
        coord_x = string_to_number(xs)
        coord_y = string_to_number(ys)

        return coord_x, coord_y

    @staticmethod
    def _from_compressed(data, curve):
        """Decode public point from compressed encoding."""
        if data[:1] not in (b"\x02", b"\x03"):
            raise MalformedPointError("Malformed compressed point encoding")

        is_even = data[:1] == b"\x02"
        x = string_to_number(data[1:])
        p = curve.p()
        alpha = (pow(x, 3, p) + (curve.a() * x) + curve.b()) % p
        try:
            beta = numbertheory.square_root_mod_prime(alpha, p)
        except numbertheory.Error as e:
            raise MalformedPointError(
                "Encoding does not correspond to a point on curve", e
            )
        if is_even == bool(beta & 1):
            y = p - beta
        else:
            y = beta
        return x, y

    @classmethod
    def _from_hybrid(cls, data, raw_encoding_length, validate_encoding):
        """Decode public point from hybrid encoding."""
        # real assert, from_bytes() should not call us with different types
        assert data[:1] in (b"\x06", b"\x07")

        # primarily use the uncompressed as it's easiest to handle
        x, y = cls._from_raw_encoding(data[1:], raw_encoding_length)

        # but validate if it's self-consistent if we're asked to do that
        if validate_encoding and (
            y & 1
            and data[:1] != b"\x07"
            or (not y & 1)
            and data[:1] != b"\x06"
        ):
            raise MalformedPointError("Inconsistent hybrid point encoding")

        return x, y

    @classmethod
    def _from_edwards(cls, curve, data):
        """Decode a point on an Edwards curve."""
        data = bytearray(data)
        p = curve.p()
        # add 1 for the sign bit and then round up
        exp_len = (bit_length(p) + 1 + 7) // 8
        if len(data) != exp_len:
            raise MalformedPointError("Point length doesn't match the curve.")
        x_0 = (data[-1] & 0x80) >> 7

        data[-1] &= 0x80 - 1

        y = bytes_to_int(data, "little")
        if GMPY:
            y = mpz(y)

        x2 = (
            (y * y - 1)
            * numbertheory.inverse_mod(curve.d() * y * y - curve.a(), p)
            % p
        )

        try:
            x = numbertheory.square_root_mod_prime(x2, p)
        except numbertheory.Error as e:
            raise MalformedPointError(
                "Encoding does not correspond to a point on curve", e
            )

        if x % 2 != x_0:
            x = -x % p

        return x, y

    @classmethod
    def from_bytes(
        cls, curve, data, validate_encoding=True, valid_encodings=None
    ):
        """
        Initialise the object from byte encoding of a point.

        The method does accept and automatically detect the type of point
        encoding used. It supports the :term:`raw encoding`,
        :term:`uncompressed`, :term:`compressed`, and :term:`hybrid` encodings.

        Note: generally you will want to call the ``from_bytes()`` method of
        either a child class, PointJacobi or Point.

        :param data: single point encoding of the public key
        :type data: :term:`bytes-like object`
        :param curve: the curve on which the public key is expected to lay
        :type curve: ~ecdsa.ellipticcurve.CurveFp
        :param validate_encoding: whether to verify that the encoding of the
            point is self-consistent, defaults to True, has effect only
            on ``hybrid`` encoding
        :type validate_encoding: bool
        :param valid_encodings: list of acceptable point encoding formats,
            supported ones are: :term:`uncompressed`, :term:`compressed`,
            :term:`hybrid`, and :term:`raw encoding` (specified with ``raw``
            name). All formats by default (specified with ``None``).
        :type valid_encodings: :term:`set-like object`

        :raises `~ecdsa.errors.MalformedPointError`: if the public point does
            not lay on the curve or the encoding is invalid

        :return: x and y coordinates of the encoded point
        :rtype: tuple(int, int)
        """
        if not valid_encodings:
            valid_encodings = set(
                ["uncompressed", "compressed", "hybrid", "raw"]
            )
        if not all(
            i in set(("uncompressed", "compressed", "hybrid", "raw"))
            for i in valid_encodings
        ):
            raise ValueError(
                "Only uncompressed, compressed, hybrid or raw encoding "
                "supported."
            )
        data = normalise_bytes(data)

        if isinstance(curve, CurveEdTw):
            return cls._from_edwards(curve, data)

        key_len = len(data)
        raw_encoding_length = 2 * orderlen(curve.p())
        if key_len == raw_encoding_length and "raw" in valid_encodings:
            coord_x, coord_y = cls._from_raw_encoding(
                data, raw_encoding_length
            )
        elif key_len == raw_encoding_length + 1 and (
            "hybrid" in valid_encodings or "uncompressed" in valid_encodings
        ):
            if data[:1] in (b"\x06", b"\x07") and "hybrid" in valid_encodings:
                coord_x, coord_y = cls._from_hybrid(
                    data, raw_encoding_length, validate_encoding
                )
            elif data[:1] == b"\x04" and "uncompressed" in valid_encodings:
                coord_x, coord_y = cls._from_raw_encoding(
                    data[1:], raw_encoding_length
                )
            else:
                raise MalformedPointError(
                    "Invalid X9.62 encoding of the public point"
                )
        elif (
            key_len == raw_encoding_length // 2 + 1
            and "compressed" in valid_encodings
        ):
            coord_x, coord_y = cls._from_compressed(data, curve)
        else:
            raise MalformedPointError(
                "Length of string does not match lengths of "
                "any of the enabled ({0}) encodings of the "
                "curve.".format(", ".join(valid_encodings))
            )
        return coord_x, coord_y

    def _raw_encode(self):
        """Convert the point to the :term:`raw encoding`."""
        prime = self.curve().p()
        x_str = number_to_string(self.x(), prime)
        y_str = number_to_string(self.y(), prime)
        return x_str + y_str

    def _compressed_encode(self):
        """Encode the point into the compressed form."""
        prime = self.curve().p()
        x_str = number_to_string(self.x(), prime)
        if self.y() & 1:
            return b"\x03" + x_str
        return b"\x02" + x_str

    def _hybrid_encode(self):
        """Encode the point into the hybrid form."""
        raw_enc = self._raw_encode()
        if self.y() & 1:
            return b"\x07" + raw_enc
        return b"\x06" + raw_enc

    def _edwards_encode(self):
        """Encode the point according to RFC8032 encoding."""
        self.scale()
        x, y, p = self.x(), self.y(), self.curve().p()

        # add 1 for the sign bit and then round up
        enc_len = (bit_length(p) + 1 + 7) // 8
        y_str = int_to_bytes(y, enc_len, "little")
        if x % 2:
            y_str[-1] |= 0x80
        return y_str

    def to_bytes(self, encoding="raw"):
        """
        Convert the point to a byte string.

        The method by default uses the :term:`raw encoding` (specified
        by `encoding="raw"`. It can also output points in :term:`uncompressed`,
        :term:`compressed`, and :term:`hybrid` formats.

        For points on Edwards curves `encoding` is ignored and only the
        encoding defined in RFC 8032 is supported.

        :return: :term:`raw encoding` of a public on the curve
        :rtype: bytes
        """
        assert encoding in ("raw", "uncompressed", "compressed", "hybrid")
        curve = self.curve()
        if isinstance(curve, CurveEdTw):
            return self._edwards_encode()
        elif encoding == "raw":
            return self._raw_encode()
        elif encoding == "uncompressed":
            return b"\x04" + self._raw_encode()
        elif encoding == "hybrid":
            return self._hybrid_encode()
        else:
            return self._compressed_encode()

    @staticmethod
    def _naf(mult):
        """Calculate non-adjacent form of number."""
        ret = []
        while mult:
            if mult % 2:
                nd = mult % 4
                if nd >= 2:
                    nd -= 4
                ret.append(nd)
                mult -= nd
            else:
                ret.append(0)
            mult //= 2
        return ret

    @staticmethod
    def _integer_multiplier(mult):
        """
        Return a multiplier as a plain integer, refusing anything else.

        The recodings read the multiplier's bits with shifts, masks and
        divisions.  A value that stands for no integer -- the decimal digits of
        a string, a float with a fraction to truncate -- would multiply by a
        number the caller never asked for, and one that is not numeric at all
        would surface as whichever error the first arithmetic operation happens
        to raise, which differs between the integer implementations this module
        can use.  Both are refused here, with one and the same exception, ahead
        of everything else a multiplication does with the multiplier.

        `operator.index()` is asked first, and it is the whole of the question
        for every multiplier this library itself forms: `int`, `bool` and the
        ``mpz`` of both gmpy releases answer it losslessly, and unlike a direct
        ``__index__()`` call it also refuses a method answering with something
        that is not an integer.  Only the type is read on that path, never the
        value, so no secret-bearing multiplier is ever looked at.

        A value of some other type may still stand for one integer and nothing
        else -- a `float`, a `Fraction` or a `Decimal` with no fractional part
        -- and releases up to 0.19.1 answered those with the multiple that
        integer asks for.  That answer is kept: such a value is converted and
        accepted, and the conversion is what makes accepting it safe, since the
        integer is what reaches the recodings and the original never reaches
        the arithmetic.  Release 1.17 of the older gmpy binding answers a float
        taken modulo a number as wide as a curve order by attempting an
        allocation of exabytes and taking the interpreter down with it, and
        that is reachable only by letting the float itself through.

        What is refused is therefore what loses something on the way to an
        integer, whether it converts or not: a fraction of one half, a float
        that is not a number or is larger than any, a string of digits, an
        empty container, a complex number.  Releases up to 0.19.1 answered some
        of those -- with the point for a different multiplier, with the point
        itself, or with the point at infinity -- and none of those answers is
        the multiple the caller asked for, so a refusal naming the type is
        offered in their place.  Whether anything is lost is asked of the value
        in its own type before any integer is built from it, so a value naming
        an integer too wide for its own type to hold is refused as cheaply as
        those releases refused it rather than by allocating one.  The value is
        read only on this path, which no multiplier of this library's own
        reaches.

        A plain `int` is returned because gmp object creation costs
        cumulatively more here than the speedup gmp gives the recodings, the
        same reason `mul_add()` coerces its multipliers.

        :raises TypeError: if the multiplier stands for no integer, or offers a
            ``__index__()`` that does not answer with one

        :return: the integer the multiplier stands for
        :rtype: int
        """
        try:
            return operator.index(mult)
        except TypeError:
            pass
        try:
            # Whether the value has a fraction is asked of the value in its
            # own type, which builds no integer to find out: division by one
            # answers a `float` with a `float` and a `Decimal` with a
            # `Decimal`, and answers a `Decimal` whose integral part is wider
            # than its own context can hold with `InvalidOperation` -- as
            # cheaply as releases up to 0.19.1 refused that value, and without
            # the allocation that converting `Decimal("1e1000000000")`
            # outright would ask for.  A float that is not a number, and one
            # larger than any number, each divide to something that is not a
            # number and so are unequal to what they divided to; a value that
            # is not numeric at all offers no such division and raises.  Only
            # once a value has answered that it loses nothing is an integer
            # built from it, and only if the two still compare equal is that
            # integer the one the caller asked to multiply by.
            if mult == mult // 1 and int(mult) == mult:
                return int(mult)
            # Every failure of those questions is a way of standing for no
            # integer, and each has to arrive as the single exception raised
            # below rather than as itself.  Two reach here from the division:
            # `//` answers a type it cannot divide -- a string, a container, a
            # complex number -- with `TypeError`, and answers a `Decimal` too
            # wide for its context with `InvalidOperation`, an
            # `ArithmeticError` that no integer conversion would raise.  A
            # conversion that raises rather than answering is caught here too,
            # so nothing a type does in place of converting is passed on.
        except Exception:
            pass
        # re-raised rather than propagated so that the message names the type
        # the caller passed; the one `operator.index()` raises names it only
        # when the multiplier offers no `__index__()` at all
        raise TypeError(
            "multiplier must be an integer, not %s" % type(mult).__name__
        )

    @staticmethod
    def _fixed_window(order):
        """
        Digit width the fixed length recoding can use for a point of `order`.

        Returns ``_MUL_WINDOW`` when the order can carry it and zero when the
        order cannot be used at all, in which case `_fixed_ladder_usable()` is
        false and the multiplication is recoded against the curve instead, see
        `_curve_ladder_usable()`, or falls back to the non-adjacent form
        recoding of `_naf()` where not even that applies.  Nothing in between,
        deliberately: a narrower second width would make the width a point is
        recoded at a property of an order the caller chooses.

        Two properties of the order are needed, neither guaranteed by a public
        constructor, both consequences of the mechanism rather than thresholds
        picked here.  All twenty six registered curves satisfy both, each
        declaring an odd order of 110 bits or more:

        * **known and odd**, because `_canonical_scalar()` makes a multiplier
          odd by adding a multiple of the order and `_fixed_digits()` requires
          an odd input.  An even order also lets a partial result reach the
          point at infinity part way through the ladder, which would make the
          sequence of addition formulas follow the multiplier again.  ECDSA and
          SEC 1 require a prime generator order, so no conforming parameter set
          is affected.
        * **larger than the largest digit**, ``2 ** window - 1``, since a digit
          names an odd multiple of the point and where the order is no larger
          one of those multiples is the point at infinity, which the affine
          entries of a table cannot hold.  Nothing is given up: a group that
          small yields any multiplier to a search of at most that many tries.

        A point either property fails for keeps the behaviour of releases up to
        0.19.1, except that a point which reports no order at all is recoded
        against its curve: an unknown order is the one case of the two above
        where nothing about the group is being claimed, and
        `_curve_scalar_width()` bounds every order the curve could hold.
        """
        if not order or not order & 1:
            return 0
        window = _MUL_WINDOW
        if int(order) <= (1 << window) - 1:
            return 0
        return window

    @classmethod
    def _fixed_ladder_usable(cls, order):
        """
        Can a point of `order` use the fixed length recoding of a multiplier?

        True exactly when `_fixed_window()` finds a digit width the order can
        carry.  A point whose order it cannot -- no order, an even order, or a
        group narrower than the widest digit -- is answered by one of the other
        two paths.  A point that reports no order has its multiplier recoded
        against its curve instead, see `_curve_ladder_usable()`, which is what
        an ECDH exchange against a decoded public point takes; the remaining
        cases fall back to the non-adjacent form recoding of `_naf()`: correct,
        just not hiding the multiplier width.  Every registered curve has an
        odd order wide enough, so both are reached only when the caller gave no
        usable order, and such a point is left on them rather than rejected, as
        rejecting it would withdraw a documented way of building a point.
        """
        return bool(cls._fixed_window(order))

    @staticmethod
    def _canonical_scalar(mult, order):
        """
        Bring a multiplier to the form the fixed length recoding expects.

        Returns an odd number congruent to ``mult`` modulo ``order`` and lying
        in the two-order-wide interval starting at ``order``, whatever ``mult``
        was.  Multiplying by it gives the same point as multiplying by
        ``mult``, since ``order`` times a point of that order is the point at
        infinity.  The order is coerced to a plain integer first, so a point
        whose order is a gmp object still answers with an ordinary one.

        Two properties are what the ladders need, and both hold for every
        residue of every order they accept:

        * it is **odd**, which `_fixed_digits()` requires and which is why
          `_fixed_window()` refuses an even order: one order is added where the
          residue is even and two where it is odd, and only an odd order can
          change a parity that way.  The multiple is selected by index rather
          than by branch, so either parity costs the same;
        * it is **smaller than** ``2 ** (bit_length(order) + 2)``, since three
          orders are, which lets `_fixed_digit_count()` size a recoding from
          the public order alone.  That is the whole of what makes the point
          operation count follow the curve: no shorter multiplier is recoded
          into fewer digits, and no digit is ever zero, so none is ever
          skipped.

        Two things it deliberately does **not** do, both disclosed in
        ``SECURITY.md``.  The returned value is not of constant width --
        ``bit_length(order)`` to ``bit_length(order) + 2`` bits depending on
        the residue -- and a Python integer operation costs according to the
        limb width of its operands, so a per-operation signal remains; what is
        fixed is the point operation count, the carrier CVE-2024-23342 was
        reported on.  Nor is every degenerate addition ruled out: for at most
        two residues of any order -- none at all on some, SECP160r1 among the
        registered curves -- twice the least significant digit equals the
        value, leaving the last addition of the ladder with two equal operands,
        which `PointJacobi._mul_precompute()` and
        `PointEdwards._mul_precompute()` cost out for either curve shape.
        """
        order = int(order)
        # gmp object creation has cumulatively higher overhead than the
        # speedup we get from calculating with gmp so ensure use of int()
        residue = int(mult) % order
        # one order where the residue is even and two where it is odd; the
        # order being odd, either way the sum is odd
        return residue + order * (1 + (residue & 1))

    @staticmethod
    def _fixed_digit_count(order, window):
        """
        Number of `_fixed_digits()` digits needed for a point of `order`.

        Every canonical multiplier (see `_canonical_scalar()`) is below three
        times the order and so below ``2 ** (bit_length(order) + 2)``, whatever
        it was derived from, so covering those bits with whole windows holds
        the widest one of this order and no more.  That makes both this count
        and a multiplication's point operation count follow the public order
        alone.
        """
        return (bit_length(order) + 2 + window - 1) // window

    @staticmethod
    def _curve_scalar_width(curve):
        """
        Width in bits no scalar of a group on `curve` can reach.

        Hasse's theorem bounds the number of points of a curve over a field of
        ``p`` elements to within ``2 * sqrt(p)`` of ``p + 1``, and the order of
        any point divides that number, so every order a point of this curve can
        have -- and with it every multiplier that is a residue of such an order
        -- is below ``2 ** (bit_length(p) + 1)``.

        That is what lets a point which knows no order be multiplied at a
        fixed cost: the curve bounds the multiplier where the order cannot.
        The bound is a property of the curve and never of the value, so it is
        public, and two points of the same curve are recoded into the same
        number of digits whatever multiplies them.
        """
        return bit_length(int(curve.p())) + 1

    @classmethod
    def _curve_digit_count(cls, curve, window):
        """
        Number of `_fixed_digits()` digits a scalar of `curve` can need.

        Enough whole windows to cover `_curve_scalar_width()`, so the count --
        and with it the number of point operations a ladder driven by it
        performs -- follows the curve alone.  `_fixed_digit_count()` is that
        same measurement taken from a known order; the two differ by a digit on
        some curves, and neither follows a multiplier.
        """
        return (cls._curve_scalar_width(curve) + window - 1) // window

    @classmethod
    def _curve_ladder_usable(cls, curve, mult):
        """
        Can `mult` be recoded against `curve` rather than against an order?

        True for a multiplier some group on `curve` could hold: not negative,
        and narrower than `_curve_scalar_width()`.  Those are the multipliers a
        point of unknown order can have recoded at a fixed length, which is
        what `PointJacobi._curve_fixed_usable()` uses this for -- a public
        point decoded from an encoding carries no order, and an ECDH exchange
        multiplies one of those by the long term private key.

        The two kinds of multiplier left out are values no secret of this
        library is, and each is left out because the recoding cannot represent
        it: `_fixed_digits()` reads bits off a non-negative number, and
        bringing a wider value inside the bound would need an order to reduce
        it against.  A private key and a nonce are both drawn from
        ``[1, order)``, so neither is negative and neither reaches the bound.
        """
        return 0 <= mult < (1 << cls._curve_scalar_width(curve))

    @classmethod
    def _fixed_table_length(cls, order, window):
        """
        Number of entries the multiplication table of `order` holds.

        Every digit position holds the ``2 ** (window - 1)`` odd multiples a
        whole window reaches, so any digit the recoding can produce is answered
        by one entry of its own position.  `PointJacobi._maybe_precompute()`
        builds exactly this many and `PointJacobi.__setstate__()` uses the
        count to tell an indexable table from one it must discard.  NIST256p:
        65 positions of 8 entries, 520 in total.
        """
        return cls._fixed_digit_count(order, window) * (1 << (window - 1))

    @classmethod
    def _fixed_table_shaped(cls, table, order, arity):
        """
        Whether `table` is shaped like a table this code can index.

        A restored table (see `PointJacobi.__setstate__()`) is usable only if
        this layout would have built one of the same shape for the same order:
        `_fixed_table_length()` entries of `arity` coordinates each.  An order
        the recoding cannot use indexes no table, so nothing is shaped for it.
        Shape is checked, contents are not -- a correctly shaped table holding
        wrong multiples is accepted, as releases up to 0.19.1 accepted any
        table at all, and checking the multiples would mean recomputing them.
        """
        try:
            if not len(table):
                return False
            window = cls._fixed_window(order)
            if not window:
                return False
            if len(table) != cls._fixed_table_length(order, window):
                return False
            for entry in table:
                if len(entry) != arity:
                    return False
        except TypeError:
            # not a sized sequence of sized entries, so not a table this code
            # could have written, whatever else it may be
            return False
        return True

    @staticmethod
    def _fixed_digits(mult, count, window):
        """
        Recode an odd number as a fixed length signed digit sequence.

        Returns exactly ``count`` digits, least significant first, every one
        odd -- hence never zero -- with absolute value below ``2 ** window``,
        so a ladder driven by the sequence performs one point addition per
        digit and the addition count follows ``count`` alone, never ``mult``.
        ``mult`` must be odd and below ``2 ** (count * window)``, which
        `_canonical_scalar()` and `_fixed_digit_count()` together guarantee.
        This is the regular recoding of Joye and Tunstall; at ``window`` 1 it
        degenerates into a signed binary expansion over ``{-1, 1}``.
        """
        # gmp object creation has cumulatively higher overhead than the
        # speedup we get from calculating the digits using gmp so ensure use
        # of int()
        mult = int(mult)
        top = 1 << window
        modulus = top * 2
        digits = []
        for _ in range(count - 1):
            dig = (mult % modulus) - top
            mult = (mult - dig) >> window
            digits.append(dig)
        # each iteration keeps `mult` odd while dividing it by 2**window, so
        # after count-1 of them it is an odd number smaller than 2**window,
        # i.e. already a valid digit
        digits.append(mult)
        return digits


class PointJacobi(AbstractPoint):
    """
    Point on a short Weierstrass elliptic curve. Uses Jacobi coordinates.

    In Jacobian coordinates, there are three parameters, X, Y and Z.
    They correspond to affine parameters 'x' and 'y' like so:

    x = X / Z²
    y = Y / Z³
    """

    def __init__(self, curve, x, y, z, order=None, generator=False):
        """
        Initialise a point that uses Jacobi representation internally.

        :param CurveFp curve: curve on which the point resides
        :param int x: the X parameter of Jacobi representation (equal to x when
          converting from affine coordinates
        :param int y: the Y parameter of Jacobi representation (equal to y when
          converting from affine coordinates
        :param int z: the Z parameter of Jacobi representation (equal to 1 when
          converting from affine coordinates
        :param int order: the point order, must be non zero when using
          generator=True
        :param bool generator: the point provided is a curve generator, as
          such, it will be commonly used with scalar multiplication. This will
          cause to precompute multiplication table generation for it
        """
        super(PointJacobi, self).__init__()
        self.__curve = curve
        if GMPY:  # pragma: no branch
            self.__coords = (mpz(x), mpz(y), mpz(z))
            self.__order = order and mpz(order)
        else:  # pragma: no branch
            self.__coords = (x, y, z)
            self.__order = order
        self.__generator = generator
        self.__precompute = []

    @classmethod
    def from_bytes(
        cls,
        curve,
        data,
        validate_encoding=True,
        valid_encodings=None,
        order=None,
        generator=False,
    ):
        """
        Initialise the object from byte encoding of a point.

        The method does accept and automatically detect the type of point
        encoding used. It supports the :term:`raw encoding`,
        :term:`uncompressed`, :term:`compressed`, and :term:`hybrid` encodings.

        :param data: single point encoding of the public key
        :type data: :term:`bytes-like object`
        :param curve: the curve on which the public key is expected to lay
        :type curve: ~ecdsa.ellipticcurve.CurveFp
        :param validate_encoding: whether to verify that the encoding of the
            point is self-consistent, defaults to True, has effect only
            on ``hybrid`` encoding
        :type validate_encoding: bool
        :param valid_encodings: list of acceptable point encoding formats,
            supported ones are: :term:`uncompressed`, :term:`compressed`,
            :term:`hybrid`, and :term:`raw encoding` (specified with ``raw``
            name). All formats by default (specified with ``None``).
        :type valid_encodings: :term:`set-like object`
        :param int order: the point order, must be non zero when using
            generator=True
        :param bool generator: the point provided is a curve generator, as
            such, it will be commonly used with scalar multiplication. This
            will cause to precompute multiplication table generation for it

        :raises `~ecdsa.errors.MalformedPointError`: if the public point does
            not lay on the curve or the encoding is invalid

        :return: Point on curve
        :rtype: PointJacobi
        """
        coord_x, coord_y = super(PointJacobi, cls).from_bytes(
            curve, data, validate_encoding, valid_encodings
        )
        return PointJacobi(curve, coord_x, coord_y, 1, order, generator)

    def _maybe_precompute(self):
        """
        Build the multiplication table of a generator, once.

        For every digit position `_fixed_digits()` emits, the table holds the
        odd multiples of this point a digit in that position can select, so
        `_mul_precompute()` answers any digit with one addition of one affine
        entry.  Writing ``digits`` for `_fixed_digit_count()`, that is the
        ``digits * 2 ** (window - 1)`` entries `_fixed_table_length()` names,
        built with ``window * (digits - 1) + 1`` doublings and ``digits * (2 **
        (window - 1) - 1)`` additions.  NIST256p: 520 entries for 257 doublings
        and 455 additions.  NIST521p: 1048 entries for 521 doublings and 917
        additions.  Every later multiplication reads the finished table and
        performs no doubling at all.
        """
        if not self.__generator or self.__precompute:
            return

        order = self.__order
        assert order
        window = self._fixed_window(order)
        if not window:
            # An order the fixed length recoding cannot use also cannot index
            # this table, and one small enough to divide an odd multiple below
            # would put the point at infinity in it, which two coordinates per
            # entry cannot hold.  Leaving the table empty sends such points
            # through `__mul__`'s table-less paths, which handle every order.
            return

        # since this code will execute just once, and it's fully deterministic,
        # depend on atomicity of the last assignment to switch from empty
        # self.__precompute to filled one and just ignore the unlikely
        # situation when two threads execute it at the same time (as it won't
        # lead to inconsistent __precompute)
        odd_multiples = 1 << (window - 1)
        coord_x, coord_y, coord_z = self.__coords
        base = PointJacobi(
            self.__curve, coord_x, coord_y, coord_z, order
        ).scale()
        precompute = []
        positions = self._fixed_digit_count(order, window)

        for position in range(positions):
            # 2 * base is both the step between consecutive odd multiples of
            # base and, doubled window-1 more times, the base of the next
            # digit position
            step = base.double().scale()
            odd = base
            precompute.append((odd.x(), odd.y()))
            for _ in range(odd_multiples - 1):
                odd = (odd + step).scale()
                precompute.append((odd.x(), odd.y()))
            if position + 1 < positions:
                # every position is a whole window wide, so every one of them
                # gets the same entries; nothing follows the most significant
                # one, which is why its base alone is not advanced
                base = step
                for _ in range(window - 1):
                    base = base.double()
                base = base.scale()

        self.__precompute = precompute

    def __getstate__(self):
        # while this code can execute at the same time as _maybe_precompute()
        # is updating the __precompute or scale() is updating the __coords,
        # there is no requirement for consistency between __coords and
        # __precompute
        state = self.__dict__.copy()
        return state

    def __setstate__(self, state):
        self.__dict__.update(state)
        # The pickle container remains the instance dictionary, but the cached
        # multiplication table uses a new layout.  New code discards and
        # rebuilds old-layout caches; old code cannot safely read new-layout
        # caches.
        #
        # A restored table is kept only when this layout could have written it
        # and would index it the same way: `_fixed_table_length()` entries of
        # two coordinates each, for an order the fixed length recoding can use.
        # Any other shape -- the successive doublings a release up to 0.19.1
        # wrote, a table absent from the state, a truncated or malformed one --
        # is dropped here and `_maybe_precompute()` builds the right one on
        # first use.  Dropping raises nothing: an unrecognised cache is not a
        # broken pickle, and the point itself is restored in full by the
        # assignment above.
        #
        # The other direction cannot be guarded from here.  An older release
        # handed odd multiples to index as successive doublings has no check
        # that would notice and would answer a wrong point rather than raise;
        # that residual is accepted and recorded in `SECURITY.md`,
        # `__getstate__()` staying the plain instance dictionary every release
        # has read and written.  Both values below are read from the state and
        # not from the instance, so a state missing either key is treated like
        # any other unusable one instead of raising what no release ever raised
        # here.
        table = state.get("_PointJacobi__precompute")
        order = state.get("_PointJacobi__order")
        if not self._fixed_table_shaped(table, order, 2):
            self.__precompute = []

    def __eq__(self, other):
        """Compare for equality two points with each-other.

        Note: only points that lay on the same curve can be equal.
        """
        x1, y1, z1 = self.__coords
        if other is INFINITY:
            return not z1
        if isinstance(other, Point):
            x2, y2, z2 = other.x(), other.y(), 1
        elif isinstance(other, PointJacobi):
            x2, y2, z2 = other.__coords
        else:
            return NotImplemented
        if self.__curve != other.curve():
            return False
        p = self.__curve.p()

        zz1 = z1 * z1 % p
        zz2 = z2 * z2 % p

        # compare the fractions by bringing them to the same denominator
        # depend on short-circuit to save 4 multiplications in case of
        # inequality
        return (x1 * zz2 - x2 * zz1) % p == 0 and (
            y1 * zz2 * z2 - y2 * zz1 * z1
        ) % p == 0

    def __ne__(self, other):
        """Compare for inequality two points with each-other."""
        return not self == other

    def order(self):
        """Return the order of the point.

        None if it is undefined.
        """
        return self.__order

    def curve(self):
        """Return curve over which the point is defined."""
        return self.__curve

    def x(self):
        """
        Return affine x coordinate.

        This method should be used only when the 'y' coordinate is not needed.
        It's computationally more efficient to use `to_affine()` and then
        call x() and y() on the returned instance. Or call `scale()`
        and then x() and y() on the returned instance.
        """
        x, _, z = self.__coords
        if z == 1:
            return x
        p = self.__curve.p()
        z = numbertheory.inverse_mod(z, p)
        return x * z**2 % p

    def y(self):
        """
        Return affine y coordinate.

        This method should be used only when the 'x' coordinate is not needed.
        It's computationally more efficient to use `to_affine()` and then
        call x() and y() on the returned instance. Or call `scale()`
        and then x() and y() on the returned instance.
        """
        _, y, z = self.__coords
        if z == 1:
            return y
        p = self.__curve.p()
        z = numbertheory.inverse_mod(z, p)
        return y * z**3 % p

    def scale(self):
        """
        Return point scaled so that z == 1.

        Modifies point in place, returns self.
        """
        x, y, z = self.__coords
        if z == 1:
            return self

        # scaling is deterministic, so even if two threads execute the below
        # code at the same time, they will set __coords to the same value
        p = self.__curve.p()
        z_inv = numbertheory.inverse_mod(z, p)
        zz_inv = z_inv * z_inv % p
        x = x * zz_inv % p
        y = y * zz_inv * z_inv % p
        self.__coords = (x, y, 1)
        return self

    def to_affine(self):
        """Return point in affine form."""
        _, _, z = self.__coords
        p = self.__curve.p()
        if not (z % p):
            return INFINITY
        self.scale()
        x, y, z = self.__coords
        assert z == 1
        return Point(self.__curve, x, y, self.__order)

    @staticmethod
    def from_affine(point, generator=False):
        """Create from an affine point.

        :param bool generator: set to True to make the point to precalculate
          multiplication table - useful for public point when verifying many
          signatures (around 100 or so) or for generator points of a curve.
        """
        return PointJacobi(
            point.curve(), point.x(), point.y(), 1, point.order(), generator
        )

    # please note that all the methods that use the equations from
    # hyperelliptic
    # are formatted in a way to maximise performance.
    # Things that make code faster: multiplying instead of taking to the power
    # (`xx = x * x; xxxx = xx * xx % p` is faster than `xxxx = x**4 % p` and
    # `pow(x, 4, p)`),
    # multiple assignments at the same time (`x1, x2 = self.x1, self.x2` is
    # faster than `x1 = self.x1; x2 = self.x2`),
    # similarly, sometimes the `% p` is skipped if it makes the calculation
    # faster and the result of calculation is later reduced modulo `p`

    def _double_with_z_1(self, X1, Y1, p, a):
        """Add a point to itself with z == 1."""
        # after:
        # http://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#doubling-mdbl-2007-bl
        XX, YY = X1 * X1 % p, Y1 * Y1 % p
        if not YY:
            return 0, 0, 0
        YYYY = YY * YY % p
        S = 2 * ((X1 + YY) ** 2 - XX - YYYY) % p
        M = 3 * XX + a
        T = (M * M - 2 * S) % p
        # X3 = T
        Y3 = (M * (S - T) - 8 * YYYY) % p
        Z3 = 2 * Y1 % p
        return T, Y3, Z3

    def _double(self, X1, Y1, Z1, p, a):
        """Add a point to itself, arbitrary z."""
        if Z1 == 1:
            return self._double_with_z_1(X1, Y1, p, a)
        if not Z1:
            return 0, 0, 0
        # after:
        # http://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#doubling-dbl-2007-bl
        XX, YY = X1 * X1 % p, Y1 * Y1 % p
        if not YY:
            return 0, 0, 0
        YYYY = YY * YY % p
        ZZ = Z1 * Z1 % p
        S = 2 * ((X1 + YY) ** 2 - XX - YYYY) % p
        M = (3 * XX + a * ZZ * ZZ) % p
        T = (M * M - 2 * S) % p
        # X3 = T
        Y3 = (M * (S - T) - 8 * YYYY) % p
        Z3 = ((Y1 + Z1) ** 2 - YY - ZZ) % p

        return T, Y3, Z3

    def double(self):
        """Add a point to itself."""
        X1, Y1, Z1 = self.__coords

        if not Z1:
            return INFINITY

        p, a = self.__curve.p(), self.__curve.a()

        X3, Y3, Z3 = self._double(X1, Y1, Z1, p, a)

        if not Z3:
            return INFINITY
        return PointJacobi(self.__curve, X3, Y3, Z3, self.__order)

    def _add_with_z_1(self, X1, Y1, X2, Y2, p):
        """add points when both Z1 and Z2 equal 1"""
        # after:
        # http://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#addition-mmadd-2007-bl
        H = X2 - X1
        HH = H * H
        I = 4 * HH % p
        J = H * I
        r = 2 * (Y2 - Y1)
        if not H and not r:
            return self._double_with_z_1(X1, Y1, p, self.__curve.a())
        V = X1 * I
        X3 = (r**2 - J - 2 * V) % p
        Y3 = (r * (V - X3) - 2 * Y1 * J) % p
        Z3 = 2 * H % p
        return X3, Y3, Z3

    def _add_with_z_eq(self, X1, Y1, Z1, X2, Y2, p):
        """add points when Z1 == Z2"""
        # after:
        # http://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#addition-zadd-2007-m
        A = (X2 - X1) ** 2 % p
        B = X1 * A % p
        C = X2 * A
        D = (Y2 - Y1) ** 2 % p
        if not A and not D:
            return self._double(X1, Y1, Z1, p, self.__curve.a())
        X3 = (D - B - C) % p
        Y3 = ((Y2 - Y1) * (B - X3) - Y1 * (C - B)) % p
        Z3 = Z1 * (X2 - X1) % p
        return X3, Y3, Z3

    def _add_with_z2_1(self, X1, Y1, Z1, X2, Y2, p):
        """add points when Z2 == 1"""
        # after:
        # http://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#addition-madd-2007-bl
        Z1Z1 = Z1 * Z1 % p
        U2, S2 = X2 * Z1Z1 % p, Y2 * Z1 * Z1Z1 % p
        H = (U2 - X1) % p
        HH = H * H % p
        I = 4 * HH % p
        J = H * I
        r = 2 * (S2 - Y1) % p
        if not r and not H:
            return self._double_with_z_1(X2, Y2, p, self.__curve.a())
        V = X1 * I
        X3 = (r * r - J - 2 * V) % p
        Y3 = (r * (V - X3) - 2 * Y1 * J) % p
        Z3 = ((Z1 + H) ** 2 - Z1Z1 - HH) % p
        return X3, Y3, Z3

    def _add_with_z_ne(self, X1, Y1, Z1, X2, Y2, Z2, p):
        """add points with arbitrary z"""
        # after:
        # http://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#addition-add-2007-bl
        Z1Z1 = Z1 * Z1 % p
        Z2Z2 = Z2 * Z2 % p
        U1 = X1 * Z2Z2 % p
        U2 = X2 * Z1Z1 % p
        S1 = Y1 * Z2 * Z2Z2 % p
        S2 = Y2 * Z1 * Z1Z1 % p
        H = U2 - U1
        I = 4 * H * H % p
        J = H * I % p
        r = 2 * (S2 - S1) % p
        if not H and not r:
            return self._double(X1, Y1, Z1, p, self.__curve.a())
        V = U1 * I
        X3 = (r * r - J - 2 * V) % p
        Y3 = (r * (V - X3) - 2 * S1 * J) % p
        Z3 = ((Z1 + Z2) ** 2 - Z1Z1 - Z2Z2) * H % p

        return X3, Y3, Z3

    def __radd__(self, other):
        """Add other to self."""
        return self + other

    def _add(self, X1, Y1, Z1, X2, Y2, Z2, p):
        """add two points, select fastest method."""
        if not Z1:
            return X2 % p, Y2 % p, Z2 % p
        if not Z2:
            return X1 % p, Y1 % p, Z1 % p
        if Z1 == Z2:
            if Z1 == 1:
                return self._add_with_z_1(X1, Y1, X2, Y2, p)
            return self._add_with_z_eq(X1, Y1, Z1, X2, Y2, p)
        if Z1 == 1:
            return self._add_with_z2_1(X2, Y2, Z2, X1, Y1, p)
        if Z2 == 1:
            return self._add_with_z2_1(X1, Y1, Z1, X2, Y2, p)
        return self._add_with_z_ne(X1, Y1, Z1, X2, Y2, Z2, p)

    def __add__(self, other):
        """Add two points on elliptic curve."""
        if self == INFINITY:
            return other
        if other == INFINITY:
            return self
        if isinstance(other, Point):
            other = PointJacobi.from_affine(other)
        if self.__curve != other.__curve:
            raise ValueError("The other point is on different curve")

        p = self.__curve.p()
        X1, Y1, Z1 = self.__coords
        X2, Y2, Z2 = other.__coords

        X3, Y3, Z3 = self._add(X1, Y1, Z1, X2, Y2, Z2, p)

        if not Z3:
            return INFINITY
        return PointJacobi(self.__curve, X3, Y3, Z3, self.__order)

    def __rmul__(self, other):
        """Multiply point by an integer."""
        return self * other

    @staticmethod
    def _scaled_all(points, p):
        """
        Rescale a list of Jacobi coordinates so that every Z equals 1.

        One modular inversion serves the whole list: the product of all the Z
        coordinates is inverted once and each individual inverse recovered with
        two multiplications.  Inversion being by far the costliest field
        operation here, that is what keeps the table affordable for
        `_mul_fixed()`, which rebuilds it every call.  A zero Z, the point at
        infinity, counts as one in the product and comes back as all-zero
        coordinates, so infinity is preserved -- not hypothetical, as the odd
        multiple table of `_mul_fixed()` runs past the order of a low order
        point, and a zero in the product would zero every entry.
        """
        # running products of the Z coordinates seen so far, with the point at
        # infinity counting as 1 so that it cannot zero the whole product
        prefixes = []
        acc = 1
        for coords in points:
            prefixes.append(acc)
            acc = acc * (coords[2] or 1) % p
        # walking the inverse of the whole product back down the list hands
        # each entry its own inverse for two multiplications
        inv = numbertheory.inverse_mod(acc, p)
        scaled = [None] * len(points)
        for i in range(len(points) - 1, -1, -1):
            X, Y, Z = points[i]
            z_inv = Z and inv * prefixes[i] % p
            inv = inv * (Z or 1) % p
            zz_inv = z_inv * z_inv % p
            scaled[i] = (
                X * zz_inv % p,
                Y * zz_inv * z_inv % p,
                z_inv and 1,
            )
        return scaled

    def _mul_precompute(self, other):
        """
        Multiply point by integer with precomputation table.

        `other` must be a canonical multiplier, see `_canonical_scalar()`.
        Because every digit of the recoding is non-zero, this schedules exactly
        one point addition per digit and no doublings, so the scheduled
        operation count follows the curve order alone.  Digit signs cost the
        same: both polarities of the selected entry are derived for every digit
        and one is picked out by index, so the field wide negations follow the
        digit count, never how many digits are negative.  The accumulator
        starts as the point at infinity and every entry is affine, so `_add()`
        takes its "Z1 is zero" branch on the first digit, `_add_with_z_1()` on
        the second and `_add_with_z2_1()` on all the rest -- again independent
        of the multiplier.  `mul_add()` defers to `__mul__()` when both its
        points carry a table, so verifying against a `ecdsa.keys.VerifyingKey`
        on which `precompute()` was called runs this method too, with public
        multipliers.

        Digits are consumed most significant first, which is what makes that
        branch sequence hold: the partial multiplier left above each position
        is then odd and strictly between zero and the order -- a canonical
        multiplier being below three orders, and three orders over
        ``2**window`` below one order for every order `_fixed_window()` accepts
        -- so the accumulator reaches infinity only before the first addition
        and never equals its addend or its negation.  The other direction
        provides none of that.  The exception is the least significant digit,
        for the at most two residues per order `_canonical_scalar()` describes;
        equal operands there make the addition formula substitute
        `_double_with_z_1()` internally, one field operation less rather than
        one point operation more and both dispatcher call counts unchanged.
        Both formulas compare operands after reducing modulo the field prime,
        which is why the negation applied to a table entry below is reduced
        too.
        """
        X3, Y3, Z3, p = 0, 0, 0, self.__curve.p()
        _add = self._add
        precompute = self.__precompute
        window = self._fixed_window(self.__order)
        odd_multiples = 1 << (window - 1)
        digits = self._fixed_digits(
            other, self._fixed_digit_count(self.__order, window), window
        )
        # the table is ordered by digit position, so walking the digits from
        # the most significant one means walking the table backwards
        offset = (len(digits) - 1) * odd_multiples
        for dig in reversed(digits):
            # the entries of a position are the odd multiples in increasing
            # order, and a digit's sign is applied by negating the Y coordinate
            # of the selected one.  Both polarities are derived and one picked
            # out by index, so the field wide negation is paid once per digit
            # whatever the signs are; an `if` would pay it only on the negative
            # ones and leave their count in the run time.  The negation is
            # reduced modulo the field prime because `_add_with_z_1()`, reached
            # on the second digit, compares raw coordinate differences to spot
            # equal operands: left bare it would answer the point at infinity
            # in place of the correct point of a two-digit-wide group.  One
            # reduction per digit, no result changed.
            X2, Y2 = precompute[offset + ((abs(dig) - 1) >> 1)]
            X3, Y3, Z3 = _add(X3, Y3, Z3, X2, (Y2, -Y2 % p)[dig < 0], 1, p)
            offset -= odd_multiples

        if not Z3:
            return INFINITY
        return PointJacobi(self.__curve, X3, Y3, Z3, self.__order)

    def _mul_fixed_digits(self, digits, window):
        """
        Run the fixed length ladder over `digits`, reading no table.

        Returns the raw Jacobi coordinates of the product of this point and the
        value the digits stand for.  The callers wrap them: `_mul_fixed()` for
        a point that knows a usable order, `_mul_curve_fixed()` for one that
        knows no order at all.

        Every digit `_fixed_digits()` produces is non-zero, so ``count`` of
        them schedule ``count`` additions and ``(count - 1) * window``
        doublings, plus the one doubling and ``2 ** (window - 1) - 1``
        additions that build the table of odd multiples of this point.  No
        count follows the value the digits carry.  For 65 digits and the window
        of this module, the shape of a 256 bit curve: 257 doublings, 72 adds.
        """
        p, a = self.__curve.p(), self.__curve.a()
        _double = self._double
        _add = self._add

        # odd multiples 1, 3, ..., 2**window - 1 of this point.  They are
        # accumulated in Jacobi coordinates and rescaled together at the end,
        # which lets the ladder below use one and the same addition formula
        # for every digit while paying a single modular inversion in total.
        self.scale()
        X1, Y1, _ = self.__coords
        needed = 1 << (window - 1)
        step = _double(X1, Y1, 1, p, a)
        table = [(X1, Y1, 1)]
        while len(table) < needed:
            X2, Y2, Z2 = table[-1]
            table.append(_add(X2, Y2, Z2, step[0], step[1], step[2], p))
        table = self._scaled_all(table, p)

        # The accumulator is the point at infinity before the most significant
        # digit, so the doublings that would precede that digit have nothing to
        # act on and are not performed; every digit after it is preceded by a
        # whole window of them.  Every digit still costs exactly one addition,
        # so the sequence of `_add()` branches taken is unchanged: its "Z1 is
        # zero" one on the most significant digit and its "Z2 is one" one on
        # every later one.
        X3, Y3, Z3 = 0, 0, 0
        window_doublings = range(window)
        doublings = range(0)
        for dig in reversed(digits):
            for _ in doublings:
                X3, Y3, Z3 = _double(X3, Y3, Z3, p, a)
            doublings = window_doublings
            # both polarities of the selected entry are derived and one is
            # picked out by index, and the negation is reduced modulo the field
            # prime; see `_mul_precompute()` for both
            X2, Y2, Z2 = table[(abs(dig) - 1) >> 1]
            X3, Y3, Z3 = _add(X3, Y3, Z3, X2, (Y2, -Y2 % p)[dig < 0], Z2, p)

        return X3, Y3, Z3

    def _mul_fixed(self, other):
        """
        Multiply point by integer without a precomputation table.

        Taken by a point that is not a curve generator but does know its order,
        most importantly by an ECDH exchange, where the multiplier is the long
        term private key rather than a single-use nonce.  `other` must be a
        canonical multiplier, see `_canonical_scalar()`, so the caller must
        also have established that the order is usable; an unusable one is
        handled by `__mul__()` directly.

        The point operation count is the one `_mul_fixed_digits()` describes,
        over a digit count that follows the curve order.
        """
        order = self.__order
        window = self._fixed_window(order)
        digits = self._fixed_digits(
            other, self._fixed_digit_count(order, window), window
        )
        X3, Y3, Z3 = self._mul_fixed_digits(digits, window)

        if not Z3:
            return INFINITY

        return PointJacobi(self.__curve, X3, Y3, Z3, order)

    def _mul_curve_fixed(self, other):
        """
        Multiply a point that knows no order by a non-negative integer.

        The path an ECDH exchange takes when the remote public point was
        decoded from an encoding: such an encoding carries no order and
        `ecdsa.keys.VerifyingKey` attaches none, so the multiplier -- the long
        term private key -- cannot be brought to a canonical width against one.
        `_curve_scalar_width()` supplies a width from the curve instead, and
        this schedules, for every multiplier that curve can hold, the fixed
        count `_mul_fixed_digits()` describes and one addition more.  `other`
        must satisfy `_curve_ladder_usable()`.

        Two steps make up for the missing order.  The recoding needs an odd
        value and no multiple of an unknown order can be added to supply one,
        so the multiplier is made odd by setting its lowest bit: one bitwise
        operation, no branch, and still inside the bound, which is a whole
        number of bits.  That is the multiplier itself where it was odd and one
        too many where it was even, so this point is subtracted from the
        product as well.  Both answers are derived for every multiplier and its
        parity picks one out by index, exactly as a digit's sign is applied, so
        neither parity costs an operation the other does not.

        The subtraction is that one further addition, of the negation of this
        point, which `_mul_fixed_digits()` has already scaled; the negation is
        reduced modulo the field prime for the reason `_mul_precompute()` has.
        The degenerate multipliers arrive where the ladder this replaces left
        them: a multiple of the order leaves the odd form at the point at
        infinity and the parity of an odd order keeps that answer, while one
        less than the order leaves it there and the subtraction turns it into
        the negation of this point, which is what that multiplier means.
        """
        window = _MUL_WINDOW
        digits = self._fixed_digits(
            other | 1, self._curve_digit_count(self.__curve, window), window
        )
        X3, Y3, Z3 = self._mul_fixed_digits(digits, window)

        p = self.__curve.p()
        X1, Y1, _ = self.__coords
        # the product of the multiplier one below the odd form, which is the
        # answer for an even multiplier; derived for every multiplier, and
        # picked out by index only for the parity it belongs to
        lowered = self._add(X3, Y3, Z3, X1, -Y1 % p, 1, p)
        X3, Y3, Z3 = (lowered, (X3, Y3, Z3))[other & 1]

        if not Z3:
            return INFINITY

        return PointJacobi(self.__curve, X3, Y3, Z3, self.__order)

    def _curve_fixed_usable(self, mult):
        """
        Whether `mult` is recoded against this point's curve.

        Answers the one case `_fixed_ladder_usable()` leaves open: a point that
        knows no order, which `_mul_curve_fixed()` multiplies at a fixed cost
        taken from the curve.  Such a point carries no multiplication table --
        building one needs an order, see `_maybe_precompute()`, and
        `__setstate__()` discards a restored table there is no usable order for
        -- so no table is consulted on that path.

        A point flagged as a generator but built without an order is left out.
        It cannot build the table its flag promises and `_maybe_precompute()`
        refuses it, as releases up to 0.19.1 refused it, so it keeps the older
        path where that refusal is reached exactly where it was reached before.
        Nothing in this library multiplies a secret by such a point.  Both the
        flag and the order are read from the point, never from the multiplier.
        """
        if self.__order or self.__generator:
            return False
        return self._curve_ladder_usable(self.__curve, mult)

    def __mul__(self, other):
        """Multiply point by an integer."""
        # Reads this point, not the multiplier: the point at infinity stays
        # where it is whatever multiplies it, so the answer tells nothing.
        if not self.__coords[1]:
            return INFINITY
        # To a plain integer before anything reads it, this method's own choice
        # of ladder included, so every path below reads integer bits and every
        # one of them refuses a value standing for no integer alike.  A value
        # already of an integer type is read for its type alone, never for the
        # value it holds, so no secret multiplier is ever looked at.
        other = self._integer_multiplier(other)
        order = self.__order
        fixed = self._fixed_ladder_usable(order)
        if fixed:
            # Normalise before ANY choice is made from the multiplier's value,
            # the shortcuts for zero and for one included.  Such a shortcut is
            # exactly the short circuit CVE-2024-23342 is about: it would
            # answer those two in no point operations where every other
            # multiplier pays the full fixed count, and a nonce of one is
            # reachable -- `sign_number()` accepts any value from one up.
            # Normalised, both run the same ladder at the same cost and both
            # still return what releases up to 0.19.1 returned; the answer for
            # one is picked out at the end of this method, after the work.
            multiplier = self._canonical_scalar(other, order)
        elif self._curve_fixed_usable(other):
            # No order to normalise the multiplier against, so its width comes
            # from the curve, which bounds every order a point of it can have.
            # This is the path an ECDH exchange takes against a remote public
            # point decoded from an encoding, where the multiplier is the long
            # term private key; `_mul_curve_fixed()` performs the same
            # number of point operations for every multiplier it holds.
            # Both of the shortcuts the fall-back below keeps are therefore
            # left out here, for the reason the fixed path above leaves them
            # out, and a multiplier of one is answered with this very object by
            # the same index once the work is done.
            return (self._mul_curve_fixed(other), self)[other == 1]
        else:
            # An order the fixed length recoding cannot use, or a multiplier
            # no group of this curve could hold.  Nothing to normalise against,
            # so the two shortcuts below cannot make the work follow the
            # multiplier any more than the ladder after them, and they keep
            # returning what releases up to 0.19.1 returned: the point at
            # infinity, and this very object -- order, generator flag and table
            # included -- rather than an equal but freshly built one.  No
            # multiplication of a secret arrives here, as documented below.
            if not other:
                return INFINITY
            if other == 1:
                return self
            multiplier = other
            if order:
                # order*2 as a "protection" for Minerva; kept only for the
                # orders the fixed length recoding cannot handle, see
                # `_fixed_ladder_usable()`, as it is what those releases did
                # and it keeps their results and edge case behaviour
                multiplier = other % (order * 2)
        self._maybe_precompute()
        if fixed:
            if self.__precompute:
                product = self._mul_precompute(multiplier)
            else:
                product = self._mul_fixed(multiplier)
            # A multiplier of one is answered with this very object, as
            # releases up to 0.19.1 answered it, but only after the ladder
            # above has done the work every other multiplier pays for: the
            # answer is picked out by index, not by a branch, so no multiplier
            # skips the scheduled ladder work.  The fall-back path returns the
            # same answer further up, ahead of a ladder whose work follows the
            # multiplier anyway.
            return (product, self)[other == 1]

        # The order of this point is unusable, or the multiplier is one that
        # no group of this curve could hold, so its width cannot be normalised
        # at all.  The iteration count of the ladder below tracks the bit
        # length of the multiplier -- a non-adjacent form can carry one digit
        # past that length -- and the point operation count follows with it, so
        # this ladder is not side channel hardened.
        #
        # No multiplication of a secret arrives here.  Every registered curve
        # declares an order the fixed length recoding can use, so signing, key
        # generation and EdDSA -- all of which multiply a generator built with
        # its order -- take the recoded ladder above; an ECDH exchange takes it
        # too, against the curve where the remote public point was decoded from
        # an encoding and so carries no order, and against the order where the
        # remote key came from a `ecdsa.keys.SigningKey` in this process.
        # What is left for this ladder is a point a caller built with an order
        # the recoding cannot use -- an even one, or a group no wider than a
        # single digit, neither of which any registered curve declares -- a
        # negative multiplier of a point that knows no order, one wider than
        # every group of its curve, and a point flagged as a generator without
        # an order, which `_maybe_precompute()` refuses.  `SECURITY.md` records
        # each of them.
        self = self.scale()
        X2, Y2, _ = self.__coords
        X3, Y3, Z3 = 0, 0, 0
        p, a = self.__curve.p(), self.__curve.a()
        _double = self._double
        _add = self._add
        # since adding points when at least one of them is scaled
        # is quicker, reverse the NAF order
        for i in reversed(self._naf(multiplier)):
            X3, Y3, Z3 = _double(X3, Y3, Z3, p, a)
            if i < 0:
                X3, Y3, Z3 = _add(X3, Y3, Z3, X2, -Y2, 1, p)
            elif i > 0:
                X3, Y3, Z3 = _add(X3, Y3, Z3, X2, Y2, 1, p)

        if not Z3:
            return INFINITY

        return PointJacobi(self.__curve, X3, Y3, Z3, self.__order)

    def mul_add(self, self_mul, other, other_mul):
        """
        Do two multiplications at the same time, add results.

        calculates self*self_mul + other*other_mul
        """
        if other == INFINITY or other_mul == 0:
            return self * self_mul
        if self_mul == 0:
            return other * other_mul
        if not isinstance(other, PointJacobi):
            other = PointJacobi.from_affine(other)
        # when the points have precomputed answers, then multiplying them alone
        # is faster (as it walks the precomputation table and needs no point
        # doublings)
        self._maybe_precompute()
        other._maybe_precompute()
        if self.__precompute and other.__precompute:
            return self * self_mul + other * other_mul

        if self.__order:
            self_mul = self_mul % self.__order
            other_mul = other_mul % self.__order

        # (X3, Y3, Z3) is the accumulator
        X3, Y3, Z3 = 0, 0, 0
        p, a = self.__curve.p(), self.__curve.a()

        # as we have 6 unique points to work with, we can't scale all of them,
        # but do scale the ones that are used most often
        self.scale()
        X1, Y1, Z1 = self.__coords
        other.scale()
        X2, Y2, Z2 = other.__coords

        _double = self._double
        _add = self._add

        # with NAF we have 3 options: no add, subtract, add
        # so with 2 points, we have 9 combinations:
        # 0, -A, +A, -B, -A-B, +A-B, +B, -A+B, +A+B
        # so we need 4 combined points:
        mAmB_X, mAmB_Y, mAmB_Z = _add(X1, -Y1, Z1, X2, -Y2, Z2, p)
        pAmB_X, pAmB_Y, pAmB_Z = _add(X1, Y1, Z1, X2, -Y2, Z2, p)
        mApB_X, mApB_Y, mApB_Z = pAmB_X, -pAmB_Y, pAmB_Z
        pApB_X, pApB_Y, pApB_Z = mAmB_X, -mAmB_Y, mAmB_Z
        # when the self and other sum to infinity, we need to add them
        # one by one to get correct result but as that's very unlikely to
        # happen in regular operation, we don't need to optimise this case
        if not pApB_Z:
            return self * self_mul + other * other_mul

        # gmp object creation has cumulatively higher overhead than the
        # speedup we get from calculating the NAF using gmp so ensure use
        # of int()
        self_naf = list(reversed(self._naf(int(self_mul))))
        other_naf = list(reversed(self._naf(int(other_mul))))
        # ensure that the lists are the same length (zip() will truncate
        # longer one otherwise)
        if len(self_naf) < len(other_naf):
            self_naf = [0] * (len(other_naf) - len(self_naf)) + self_naf
        elif len(self_naf) > len(other_naf):
            other_naf = [0] * (len(self_naf) - len(other_naf)) + other_naf

        for A, B in zip(self_naf, other_naf):
            X3, Y3, Z3 = _double(X3, Y3, Z3, p, a)

            # conditions ordered from most to least likely
            if A == 0:
                if B == 0:
                    pass
                elif B < 0:
                    X3, Y3, Z3 = _add(X3, Y3, Z3, X2, -Y2, Z2, p)
                else:
                    assert B > 0
                    X3, Y3, Z3 = _add(X3, Y3, Z3, X2, Y2, Z2, p)
            elif A < 0:
                if B == 0:
                    X3, Y3, Z3 = _add(X3, Y3, Z3, X1, -Y1, Z1, p)
                elif B < 0:
                    X3, Y3, Z3 = _add(X3, Y3, Z3, mAmB_X, mAmB_Y, mAmB_Z, p)
                else:
                    assert B > 0
                    X3, Y3, Z3 = _add(X3, Y3, Z3, mApB_X, mApB_Y, mApB_Z, p)
            else:
                assert A > 0
                if B == 0:
                    X3, Y3, Z3 = _add(X3, Y3, Z3, X1, Y1, Z1, p)
                elif B < 0:
                    X3, Y3, Z3 = _add(X3, Y3, Z3, pAmB_X, pAmB_Y, pAmB_Z, p)
                else:
                    assert B > 0
                    X3, Y3, Z3 = _add(X3, Y3, Z3, pApB_X, pApB_Y, pApB_Z, p)

        if not Z3:
            return INFINITY

        return PointJacobi(self.__curve, X3, Y3, Z3, self.__order)

    def __neg__(self):
        """Return negated point."""
        x, y, z = self.__coords
        return PointJacobi(self.__curve, x, -y, z, self.__order)


class Point(AbstractPoint):
    """A point on a short Weierstrass elliptic curve. Altering x and y is
    forbidden, but they can be read by the x() and y() methods."""

    def __init__(self, curve, x, y, order=None):
        """curve, x, y, order; order (optional) is the order of this point."""
        super(Point, self).__init__()
        self.__curve = curve
        if GMPY:
            self.__x = x and mpz(x)
            self.__y = y and mpz(y)
            self.__order = order and mpz(order)
        else:
            self.__x = x
            self.__y = y
            self.__order = order
        # self.curve is allowed to be None only for INFINITY:
        if self.__curve:
            assert self.__curve.contains_point(x, y)
        # for curves with cofactor 1, all points that are on the curve are
        # scalar multiples of the base point, so performing multiplication is
        # not necessary to verify that. See Section 3.2.2.1 of SEC 1 v2
        if curve and curve.cofactor() != 1 and order:
            assert self * order == INFINITY

    @classmethod
    def from_bytes(
        cls,
        curve,
        data,
        validate_encoding=True,
        valid_encodings=None,
        order=None,
    ):
        """
        Initialise the object from byte encoding of a point.

        The method does accept and automatically detect the type of point
        encoding used. It supports the :term:`raw encoding`,
        :term:`uncompressed`, :term:`compressed`, and :term:`hybrid` encodings.

        :param data: single point encoding of the public key
        :type data: :term:`bytes-like object`
        :param curve: the curve on which the public key is expected to lay
        :type curve: ~ecdsa.ellipticcurve.CurveFp
        :param validate_encoding: whether to verify that the encoding of the
            point is self-consistent, defaults to True, has effect only
            on ``hybrid`` encoding
        :type validate_encoding: bool
        :param valid_encodings: list of acceptable point encoding formats,
            supported ones are: :term:`uncompressed`, :term:`compressed`,
            :term:`hybrid`, and :term:`raw encoding` (specified with ``raw``
            name). All formats by default (specified with ``None``).
        :type valid_encodings: :term:`set-like object`
        :param int order: the point order, must be non zero when using
            generator=True

        :raises `~ecdsa.errors.MalformedPointError`: if the public point does
            not lay on the curve or the encoding is invalid

        :return: Point on curve
        :rtype: Point
        """
        coord_x, coord_y = super(Point, cls).from_bytes(
            curve, data, validate_encoding, valid_encodings
        )
        return Point(curve, coord_x, coord_y, order)

    def __eq__(self, other):
        """Return True if the points are identical, False otherwise.

        Note: only points that lay on the same curve can be equal.
        """
        if other is INFINITY:
            return self.__x is None or self.__y is None
        if isinstance(other, Point):
            return (
                self.__curve == other.__curve
                and self.__x == other.__x
                and self.__y == other.__y
            )
        return NotImplemented

    def __ne__(self, other):
        """Returns False if points are identical, True otherwise."""
        return not self == other

    def __neg__(self):
        return Point(self.__curve, self.__x, self.__curve.p() - self.__y)

    def __add__(self, other):
        """Add one point to another point."""

        # X9.62 B.3:

        if not isinstance(other, Point):
            return NotImplemented
        if other == INFINITY:
            return self
        if self == INFINITY:
            return other
        assert self.__curve == other.__curve
        if self.__x == other.__x:
            if (self.__y + other.__y) % self.__curve.p() == 0:
                return INFINITY
            else:
                return self.double()

        p = self.__curve.p()

        l = (
            (other.__y - self.__y)
            * numbertheory.inverse_mod(other.__x - self.__x, p)
        ) % p

        x3 = (l * l - self.__x - other.__x) % p
        y3 = (l * (self.__x - x3) - self.__y) % p

        return Point(self.__curve, x3, y3)

    def __mul__(self, other):
        """Multiply a point by an integer."""
        # Reads this point and not the multiplier: the point at infinity stays
        # where it is whatever multiplies it, and releases up to 0.19.1
        # answered it before looking at the multiplier, so this stays ahead of
        # the normalising step below.
        if self == INFINITY:
            return INFINITY
        # To a plain integer before anything reads it, this method's own choice
        # of ladder included; see `PointJacobi.__mul__()`.
        other = self._integer_multiplier(other)

        # The X9.62 D.3.2 ladder further down performs a number of point
        # operations that follows the multiplier, and each dispatches on the
        # relation between its operands, so it cannot hide a secret multiplier.
        # Points whose order supports it hand the work to the Jacobi coordinate
        # implementation, which schedules a fixed number of operations in a
        # fixed sequence, and convert the result back.  Nothing is answered
        # ahead of that hand-off -- not zero, not one, not a multiple of the
        # order, not a negative multiplier -- because every such shortcut is
        # the short circuit CVE-2024-23342 is about.
        order = self.__order
        if self._fixed_ladder_usable(order):
            product = (
                PointJacobi(self.__curve, self.__x, self.__y, 1, order) * other
            )
            if product == INFINITY:
                return INFINITY
            # For every multiplier but one the order is deliberately not
            # carried over, matching what `__add__()` and `double()` return and
            # so what releases up to 0.19.1 returned here.  For a multiplier of
            # one those releases returned this very object, order and all, and
            # so does this: the answer is picked out by index once the ladder
            # above has done the work every other multiplier pays for, not by a
            # branch that skips the scheduled work.
            return (Point(self.__curve, product.x(), product.y()), self)[
                other == 1
            ]

        # Reached for an order the fixed length recoding cannot use and for no
        # order at all.  A ladder whose length follows the multiplier is
        # avoided above rather than repaired here: this one is left exactly as
        # releases up to 0.19.1 wrote it, down to which shortcut answers which
        # multiplier, because a point reaching it has no usable order to
        # normalise a multiplier against and so nothing to gain from a rewrite:
        #
        #  * a point reporting no order cannot have a multiplier reduced
        #    against one, so there is nothing to hand the recoding;
        #  * an even order admits no odd congruent multiplier, which is what
        #    `_fixed_digits()` recodes;
        #  * an order no larger than the largest digit the recoding emits is a
        #    group in which a table entry would be the point at infinity, which
        #    affine coordinates cannot hold -- and a group that small yields
        #    any multiplier to a search of at most that many tries, so a timing
        #    difference tells an attacker nothing new.  See `_fixed_window()`;
        #  * every curve this library registers declares a usable order, so no
        #    signature, key generation or ECDH operation arrives here for want
        #    of one.

        def leftmost_bit(x):
            assert x > 0
            result = 1
            while result <= x:
                result = 2 * result
            return result // 2

        e = other
        if e == 0 or (self.__order and e % self.__order == 0):
            return INFINITY
        # the test for this point being the point at infinity, which releases
        # up to 0.19.1 made here, is made at the top of this method instead:
        # it has to come ahead of the normalising step, which those releases
        # did not have, and making it twice would leave the second one
        # unreachable
        if e < 0:
            return (-self) * (-e)

        # From X9.62 D.3.2:

        e3 = 3 * e
        negative_self = Point(
            self.__curve,
            self.__x,
            (-self.__y) % self.__curve.p(),
            self.__order,
        )
        i = leftmost_bit(e3) // 2
        result = self
        while i > 1:
            result = result.double()
            if (e3 & i) != 0 and (e & i) == 0:
                result = result + self
            if (e3 & i) == 0 and (e & i) != 0:
                result = result + negative_self
            i = i // 2

        return result

    def __rmul__(self, other):
        """Multiply a point by an integer."""

        return self * other

    def __str__(self):
        if self == INFINITY:
            return "infinity"
        return "(%d,%d)" % (self.__x, self.__y)

    def double(self):
        """Return a new point that is twice the old."""
        if self == INFINITY:
            return INFINITY

        # X9.62 B.3:

        p = self.__curve.p()
        a = self.__curve.a()

        l = (
            (3 * self.__x * self.__x + a)
            * numbertheory.inverse_mod(2 * self.__y, p)
        ) % p

        if not l:
            return INFINITY

        x3 = (l * l - 2 * self.__x) % p
        y3 = (l * (self.__x - x3) - self.__y) % p

        return Point(self.__curve, x3, y3)

    def x(self):
        return self.__x

    def y(self):
        return self.__y

    def curve(self):
        return self.__curve

    def order(self):
        return self.__order


class PointEdwards(AbstractPoint):
    """Point on Twisted Edwards curve.

    Internally represents the coordinates on the curve using four parameters,
    X, Y, Z, T. They correspond to affine parameters 'x' and 'y' like so:

    x = X / Z
    y = Y / Z
    x*y = T / Z
    """

    def __init__(self, curve, x, y, z, t, order=None, generator=False):
        """
        Initialise a point that uses the extended coordinates internally.
        """
        super(PointEdwards, self).__init__()
        self.__curve = curve
        if GMPY:  # pragma: no branch
            self.__coords = (mpz(x), mpz(y), mpz(z), mpz(t))
            self.__order = order and mpz(order)
        else:  # pragma: no branch
            self.__coords = (x, y, z, t)
            self.__order = order
        self.__generator = generator
        self.__precompute = []

    @classmethod
    def from_bytes(
        cls,
        curve,
        data,
        validate_encoding=None,
        valid_encodings=None,
        order=None,
        generator=False,
    ):
        """
        Initialise the object from byte encoding of a point.

        `validate_encoding` and `valid_encodings` are provided for
        compatibility with Weierstrass curves, they are ignored for Edwards
        points.

        :param data: single point encoding of the public key
        :type data: :term:`bytes-like object`
        :param curve: the curve on which the public key is expected to lay
        :type curve: ecdsa.ellipticcurve.CurveEdTw
        :param None validate_encoding: Ignored, encoding is always validated
        :param None valid_encodings: Ignored, there is just one encoding
            supported
        :param int order: the point order, must be non zero when using
            generator=True
        :param bool generator: Flag to mark the point as a curve generator,
            this will cause the library to pre-compute some values to
            make repeated usages of the point much faster

        :raises `~ecdsa.errors.MalformedPointError`: if the public point does
            not lay on the curve or the encoding is invalid

        :return: Initialised point on an Edwards curve
        :rtype: PointEdwards
        """
        coord_x, coord_y = super(PointEdwards, cls).from_bytes(
            curve, data, validate_encoding, valid_encodings
        )
        return PointEdwards(
            curve, coord_x, coord_y, 1, coord_x * coord_y, order, generator
        )

    def _maybe_precompute(self):
        """
        Build the multiplication table of a generator, once.

        Same layout, entry count and build cost as the table
        `PointJacobi._maybe_precompute()` builds, except that entries are
        ``(x, y, x * y % p)`` triples rather than pairs, as this curve type's
        addition formula consumes that product.  Ed25519: 512 entries for 253
        doublings and 448 additions.  Ed448: 896 entries for 445 doublings and
        784 additions.
        """
        if not self.__generator or self.__precompute:
            return self.__precompute

        order = self.__order
        assert order
        window = self._fixed_window(order)
        if not window:
            # see the identical guard in `PointJacobi._maybe_precompute()`
            return self.__precompute

        # since this code will execute just once, and it's fully deterministic,
        # depend on atomicity of the last assignment to switch from empty
        # self.__precompute to filled one and just ignore the unlikely
        # situation when two threads execute it at the same time (as it won't
        # lead to inconsistent __precompute)
        odd_multiples = 1 << (window - 1)
        coord_x, coord_y, coord_z, coord_t = self.__coords
        prime = self.__curve.p()

        base = PointEdwards(
            self.__curve, coord_x, coord_y, coord_z, coord_t, order
        ).scale()
        precompute = []
        positions = self._fixed_digit_count(order, window)

        for position in range(positions):
            # 2 * base is both the step between consecutive odd multiples of
            # base and, doubled window-1 more times, the base of the next
            # digit position; it doesn't need to be scaled as the addition
            # formula of this curve type is the same whatever z is
            step = base.double()
            odd = base
            coord_x, coord_y = odd.x(), odd.y()
            precompute.append((coord_x, coord_y, coord_x * coord_y % prime))
            for _ in range(odd_multiples - 1):
                odd = (odd + step).scale()
                coord_x, coord_y = odd.x(), odd.y()
                precompute.append(
                    (coord_x, coord_y, coord_x * coord_y % prime)
                )
            if position + 1 < positions:
                # see the same step in `PointJacobi._maybe_precompute()`: every
                # position is a whole window wide and only the most significant
                # one, which nothing follows, has its base left unadvanced
                base = step
                for _ in range(window - 1):
                    base = base.double()
                base = base.scale()

        self.__precompute = precompute
        return self.__precompute

    def __setstate__(self, state):
        # No `__getstate__` is defined for this class, here or in any release
        # up to 0.19.1, so the state is the plain instance dictionary and
        # carries the multiplication table with it.  Same rule as
        # `PointJacobi.__setstate__()`, which carries the full reasoning, with
        # the three coordinates an entry of this curve type holds instead of
        # two.
        self.__dict__.update(state)
        table = state.get("_PointEdwards__precompute")
        order = state.get("_PointEdwards__order")
        if not self._fixed_table_shaped(table, order, 3):
            self.__precompute = []

    def x(self):
        """Return affine x coordinate."""
        X1, _, Z1, _ = self.__coords
        if Z1 == 1:
            return X1
        p = self.__curve.p()
        z_inv = numbertheory.inverse_mod(Z1, p)
        return X1 * z_inv % p

    def y(self):
        """Return affine y coordinate."""
        _, Y1, Z1, _ = self.__coords
        if Z1 == 1:
            return Y1
        p = self.__curve.p()
        z_inv = numbertheory.inverse_mod(Z1, p)
        return Y1 * z_inv % p

    def curve(self):
        """Return the curve of the point."""
        return self.__curve

    def order(self):
        return self.__order

    def scale(self):
        """
        Return point scaled so that z == 1.

        Modifies point in place, returns self.
        """
        X1, Y1, Z1, _ = self.__coords
        if Z1 == 1:
            return self

        p = self.__curve.p()
        z_inv = numbertheory.inverse_mod(Z1, p)
        x = X1 * z_inv % p
        y = Y1 * z_inv % p
        t = x * y % p
        self.__coords = (x, y, 1, t)
        return self

    def __eq__(self, other):
        """Compare for equality two points with each-other.

        Note: only points on the same curve can be equal.
        """
        x1, y1, z1, t1 = self.__coords
        if other is INFINITY:
            return not x1 or not t1
        if isinstance(other, PointEdwards):
            x2, y2, z2, t2 = other.__coords
        else:
            return NotImplemented
        if self.__curve != other.curve():
            return False
        p = self.__curve.p()

        # cross multiply to eliminate divisions
        xn1 = x1 * z2 % p
        xn2 = x2 * z1 % p
        yn1 = y1 * z2 % p
        yn2 = y2 * z1 % p
        return xn1 == xn2 and yn1 == yn2

    def __ne__(self, other):
        """Compare for inequality two points with each-other."""
        return not self == other

    def _add(self, X1, Y1, Z1, T1, X2, Y2, Z2, T2, p, a):
        """add two points, assume sane parameters."""
        # after add-2008-hwcd-2
        # from https://hyperelliptic.org/EFD/g1p/auto-twisted-extended.html
        # NOTE: there are more efficient formulas for Z1 or Z2 == 1
        A = X1 * X2 % p
        B = Y1 * Y2 % p
        C = Z1 * T2 % p
        D = T1 * Z2 % p
        E = D + C
        F = ((X1 - Y1) * (X2 + Y2) + B - A) % p
        G = B + a * A
        H = D - C
        if not H:
            return self._double(X1, Y1, Z1, T1, p, a)
        X3 = E * F % p
        Y3 = G * H % p
        T3 = E * H % p
        Z3 = F * G % p

        return X3, Y3, Z3, T3

    def __add__(self, other):
        """Add point to another."""
        if other == INFINITY:
            return self
        if (
            not isinstance(other, PointEdwards)
            or self.__curve != other.__curve
        ):
            raise ValueError("The other point is on a different curve.")

        p, a = self.__curve.p(), self.__curve.a()
        X1, Y1, Z1, T1 = self.__coords
        X2, Y2, Z2, T2 = other.__coords

        X3, Y3, Z3, T3 = self._add(X1, Y1, Z1, T1, X2, Y2, Z2, T2, p, a)

        if not X3 or not T3:
            return INFINITY
        return PointEdwards(self.__curve, X3, Y3, Z3, T3, self.__order)

    def __radd__(self, other):
        """Add other to self."""
        return self + other

    def _double(self, X1, Y1, Z1, T1, p, a):
        """Double the point, assume sane parameters."""
        # after "dbl-2008-hwcd"
        # from https://hyperelliptic.org/EFD/g1p/auto-twisted-extended.html
        # NOTE: there are more efficient formulas for Z1 == 1
        A = X1 * X1 % p
        B = Y1 * Y1 % p
        C = 2 * Z1 * Z1 % p
        D = a * A % p
        E = ((X1 + Y1) * (X1 + Y1) - A - B) % p
        G = D + B
        F = G - C
        H = D - B
        X3 = E * F % p
        Y3 = G * H % p
        T3 = E * H % p
        Z3 = F * G % p

        return X3, Y3, Z3, T3

    def double(self):
        """Return point added to itself."""
        X1, Y1, Z1, T1 = self.__coords

        if not X1 or not T1:
            return INFINITY

        p, a = self.__curve.p(), self.__curve.a()

        X3, Y3, Z3, T3 = self._double(X1, Y1, Z1, T1, p, a)

        # both Ed25519 and Ed448 have prime order, so no point added to
        # itself will equal zero
        if not X3 or not T3:  # pragma: no branch
            return INFINITY
        return PointEdwards(self.__curve, X3, Y3, Z3, T3, self.__order)

    def __rmul__(self, other):
        """Multiply point by an integer."""
        return self * other

    def _mul_precompute(self, other):
        """
        Multiply point by integer with precomputation table.

        `other` must be a canonical multiplier, see `_canonical_scalar()`.
        Because every digit of the recoding is non-zero, this schedules exactly
        one point addition per digit and no point doublings, so the scheduled
        operation count is a function of the curve order alone.  Digit signs
        cost the same: both polarities of the selected entry are derived for
        every digit and the answer picked out by index, so the field wide
        negations -- two per digit here, as the product of the affine
        coordinates is negated along with the x one -- follow the digit count,
        never how many digits are negative.

        Digits are consumed most significant first for the reason spelled out
        in `PointJacobi._mul_precompute()`: it keeps every accumulator away
        from its addend, and this curve type's addition formula falls back to
        the doubling formula when handed two operands sharing the product of
        affine coordinates.  Within the odd order subgroup that needs the
        operands to be equal, the at most four points sharing such a product
        differing by a point of even order.  The least significant digit is the
        one case left open, for one residue of Ed25519's order and one of
        Ed448's; unlike the Weierstrass ladder this one pays a counted doubling
        there, making the doubling count of a multiplication one rather than
        zero.  ``SECURITY.md`` records the residual, whose share of either
        curve's multipliers is below two to the power of minus two hundred and
        fifty.
        """
        X3, Y3, Z3, T3, p, a = 0, 1, 1, 0, self.__curve.p(), self.__curve.a()
        _add = self._add
        precompute = self.__precompute
        window = self._fixed_window(self.__order)
        odd_multiples = 1 << (window - 1)
        digits = self._fixed_digits(
            other, self._fixed_digit_count(self.__order, window), window
        )
        # the table is ordered by digit position, so walking the digits from
        # the most significant one means walking the table backwards
        offset = (len(digits) - 1) * odd_multiples
        for dig in reversed(digits):
            # the entries of a position are the odd multiples in increasing
            # order, and a digit's sign is applied by negating the x coordinate
            # (and with it the x*y product) of the selected one.  Both
            # polarities are derived and one picked out by index, so the two
            # field wide negations are paid once per digit whatever the signs
            # are; an `if` would pay them only on the negative ones and leave
            # their count in the run time.
            X2, Y2, T2 = precompute[offset + ((abs(dig) - 1) >> 1)]
            negative = dig < 0
            X3, Y3, Z3, T3 = _add(
                X3,
                Y3,
                Z3,
                T3,
                (X2, -X2)[negative],
                Y2,
                1,
                (T2, -T2)[negative],
                p,
                a,
            )
            offset -= odd_multiples

        if not X3 or not T3:
            return INFINITY

        return PointEdwards(self.__curve, X3, Y3, Z3, T3, self.__order)

    def _mul_fixed(self, other):
        """
        Multiply point by integer without a precomputation table.

        Taken by points of a known order that are not marked as curve
        generators.  `other` must be a canonical multiplier, see
        `_canonical_scalar()`.

        Schedules ``count * window`` doublings and ``count`` additions,
        ``count`` following the curve order, plus the one doubling and ``2 **
        (window - 1) - 1`` additions that build the table of odd multiples of
        this point.  No count follows the multiplier, save the one exception
        `_mul_precompute()` records: the at most two residues of an order whose
        least significant digit leaves the last addition with two equal
        operands pay one counted doubling more, this curve type's addition
        formula answering equal operands with the doubling one.
        """
        p, a = self.__curve.p(), self.__curve.a()
        order = self.__order
        window = self._fixed_window(order)
        _double = self._double
        _add = self._add
        digits = self._fixed_digits(
            other, self._fixed_digit_count(order, window), window
        )

        # odd multiples 1, 3, ..., 2**window - 1 of this point.  Unlike the
        # Weierstrass ladder this table needs no rescaling, as the addition
        # formula of this curve type is the same whatever z is.
        X1, Y1, Z1, T1 = self.__coords
        needed = 1 << (window - 1)
        X0, Y0, Z0, T0 = _double(X1, Y1, Z1, T1, p, a)
        table = [(X1, Y1, Z1, T1)]
        while len(table) < needed:
            X2, Y2, Z2, T2 = table[-1]
            table.append(_add(X2, Y2, Z2, T2, X0, Y0, Z0, T0, p, a))

        X3, Y3, Z3, T3 = 0, 1, 1, 0  # INFINITY in extended coordinates
        doublings = range(window)
        for dig in reversed(digits):
            for _ in doublings:
                X3, Y3, Z3, T3 = _double(X3, Y3, Z3, T3, p, a)
            # both polarities of the selected entry are derived and one is
            # picked out by index, see `_mul_precompute()`
            X2, Y2, Z2, T2 = table[(abs(dig) - 1) >> 1]
            negative = dig < 0
            X3, Y3, Z3, T3 = _add(
                X3,
                Y3,
                Z3,
                T3,
                (X2, -X2)[negative],
                Y2,
                Z2,
                (T2, -T2)[negative],
                p,
                a,
            )

        if not X3 or not T3:
            return INFINITY

        return PointEdwards(self.__curve, X3, Y3, Z3, T3, self.__order)

    def __mul__(self, other):
        """Multiply point by an integer."""
        X2, Y2, Z2, T2 = self.__coords
        # this test reads this point and not the multiplier, see
        # `PointJacobi.__mul__()`
        if not X2 or not T2:
            return INFINITY
        # to a plain integer before anything reads it, this method's own choice
        # of ladder included; see `PointJacobi.__mul__()`
        other = self._integer_multiplier(other)
        order = self.__order
        fixed = self._fixed_ladder_usable(order)
        if fixed:
            # Normalise the multiplier before ANY choice is made from it, the
            # shortcuts for a multiplier of zero or of one included; see
            # `PointJacobi.__mul__()` for why those two must not be answered
            # in fewer point operations than every other multiplier.  The
            # answer for a multiplier of one is picked out at the end of this
            # method, after the work.
            multiplier = self._canonical_scalar(other, order)
        else:
            # An order the fixed length recoding cannot use, or none at all, so
            # these two shortcuts cannot make the work depend on a multiplier
            # any more than the ladder that follows them already does, and they
            # keep returning what releases up to 0.19.1 did; again see
            # `PointJacobi.__mul__()`.
            if not other:
                return INFINITY
            if other == 1:
                return self
            multiplier = other
            if order:
                # order*2 as a "protection" for Minerva; kept only for the
                # orders the fixed length recoding cannot handle, see
                # `_fixed_ladder_usable()`, as it is what those releases did
                # and it keeps their results and edge case behaviour
                multiplier = other % (order * 2)
        precompute = self._maybe_precompute()
        if fixed:
            if precompute:
                product = self._mul_precompute(multiplier)
            else:
                product = self._mul_fixed(multiplier)
            # A multiplier of one is answered with this very object, as
            # releases up to 0.19.1 answered it, but only after the ladder
            # above has done the work every other multiplier pays for, so no
            # multiplier skips the scheduled work; see `PointJacobi.__mul__()`.
            return (product, self)[other == 1]

        X3, Y3, Z3, T3 = 0, 1, 1, 0  # INFINITY in extended coordinates
        p, a = self.__curve.p(), self.__curve.a()
        _double = self._double
        _add = self._add

        # The order of this point is unknown or unusable, so the width of the
        # multiplier cannot be normalised.  The number of iterations of the
        # ladder below tracks the bit length of the multiplier -- a
        # non-adjacent form can carry one digit further than that length -- so
        # this ladder is not side channel hardened, and a caller that builds a
        # point without a usable order and multiplies it here gets that.
        #
        # Both Edwards curves this library registers declare an order the fixed
        # length recoding can use, so the nonce of an EdDSA signature made
        # through this library never reaches this ladder; a point rebuilt from
        # an encoding carries no order and does, which
        # `eddsa.PublicKey.verify()` multiplies by a value derived from public
        # values.
        for i in reversed(self._naf(multiplier)):
            X3, Y3, Z3, T3 = _double(X3, Y3, Z3, T3, p, a)
            if i < 0:
                X3, Y3, Z3, T3 = _add(X3, Y3, Z3, T3, -X2, Y2, Z2, -T2, p, a)
            elif i > 0:
                X3, Y3, Z3, T3 = _add(X3, Y3, Z3, T3, X2, Y2, Z2, T2, p, a)

        if not X3 or not T3:
            return INFINITY

        return PointEdwards(self.__curve, X3, Y3, Z3, T3, self.__order)


# This one point is the Point At Infinity for all purposes:
INFINITY = Point(None, None, None)
