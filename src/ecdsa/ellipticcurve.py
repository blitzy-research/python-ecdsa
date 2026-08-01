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


# When the order of a point can be used to normalise a multiplier, see
# `AbstractPoint._fixed_ladder_usable()`, the multiplier is first replaced by
# `AbstractPoint._canonical_scalar()` with a congruent value that is odd and
# lies between the order and three times it, and so is bounded by that order
# alone, and then recoded by `AbstractPoint._fixed_digits()` into a fixed
# length sequence of non-zero digits, so that the number of point additions and
# point doublings a multiplication performs is a function of the bit length of
# that order and not of the multiplier.  The fixed digit count and the absence
# of zero digits are what fix the number of point operations; for a generator
# that holds once the precomputation table has been built, the first
# multiplication also paying for building it.  That is what keeps the bit
# length of a per signature nonce, or of the long term private key in key
# generation and ECDH, out of the number of operations; see CVE-2024-23342,
# GHSA-wj6h-64fc-37mp and OWASP ASVS 4.0 requirement 6.2.8.  The bit length of
# the canonical multiplier is not itself constant -- it takes one of the three
# values from the bit length of the order up to two more than it, decided by
# the residue -- so what a multiplier is hidden from is the count of the point
# operations, not the width of every operand they are driven by.
#
# Every multiplier that is an integer is recoded, zero and one included, and
# nothing is answered ahead of the recoding: not a multiplier of zero, not one
# of one, not a multiple of the order and not a negative one.  A short circuit
# for any of them would answer that multiplier in fewer point operations than
# the ladder spends on all the others, which is exactly the short circuit
# CVE-2024-23342 is about, and one and zero in particular are values the secret
# bearing entry points of this library accept -- a private key or a nonce of
# one is not refused by signing, key generation or ECDH -- so neither can be
# dismissed as a value no secret ever takes.  What such a multiplier gets back
# is the answer it has always got, down to the identity of the object: the
# point at infinity for a multiplier of zero or of a multiple of the order, and
# for a multiplier of one the very point that was multiplied.  That answer is
# picked out by index after the ladder has run, so it costs the work every
# other multiplier costs; it is only which of two ready answers is handed back
# that the multiplier decides, not how much work was done to get there.
#
# Reading the bits of a multiplier is all the recodings do, so a multiplier
# reaches them only as a plain integer: every multiplication first hands its
# multiplier to `AbstractPoint._integer_multiplier()`, which asks the value for
# its lossless integer through `operator.index()` and refuses anything that has
# none with one and the same `TypeError` on every path.  That refusal is
# decided by the type of the multiplier and never by its value, so it cannot
# tell one integer from another, and it is what stops a value that merely
# converts to an integer -- the decimal digits of a string, a float truncated
# towards zero -- from multiplying a point by a number its caller never asked
# for.
#
# Three paths keep the multiplier driven ladders of releases up to 0.19.1
# instead: a point constructed without an order, which has nothing to normalise
# a multiplier against; a point whose order the fixed length recoding cannot
# use, which no curve this library registers declares; and the combined
# `PointJacobi.mul_add()` used to verify signatures, whose multipliers are
# derived from public values.  The number of point operations of the first two
# follows the multiplier, so neither of them is side channel hardened, and a
# caller that constructs such a point through the public constructors of this
# module and multiplies it itself gets that unhardened ladder.  What is claimed
# is narrower.  Signing, key generation and EdDSA
# reach the recoded ladder for every curve this library registers, because the
# generator they multiply is built with its order.  ECDH reaches it only for a
# remote public point that carries one: a point that arrives from an encoding
# -- `VerifyingKey.from_string()`, and so the DER, PEM and SSH readers built on
# it -- is built without an order and nothing attaches one to it afterwards, so
# multiplying it by a private key takes the fall-back ladder, whose point
# doubling count follows the bit length of that private key.  A remote public
# key handed over as a `VerifyingKey` this process derived from a `SigningKey`
# does carry the order and is recoded.  That residual exposure is recorded in
# `SECURITY.md`; removing it needs an order attached where public points are
# decoded, which is not in this module.
#
# The number of operations, and the width of the multiplier they are driven
# by, are all this hides.  The individual costs of those operations are not
# uniform: Python integers take time proportional to their magnitude and, as
# the comment in front of `PointJacobi._double_with_z_1()` explains, the
# reduction modulo the field prime is deliberately skipped where that is
# faster, so the coordinates the operations are performed on vary in width even
# where nothing about the multiplier does.
#
# Width in bits of the digits the multiplier is recoded into, and so of the
# odd multiples a precomputation table holds per digit position: a wider one
# means fewer additions per multiplication against a larger table.  It is the
# only width the recoding uses.  A narrower one cannot be made to work for any
# order at all -- see `AbstractPoint._fixed_window()`, which is where the width
# an order can carry is decided and where that is worked out -- so an order too
# narrow to carry this one is left on the multiplier driven ladder instead of
# being recoded more narrowly.  Every order any curve this library registers
# declares is far wide enough.
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

        The recodings a multiplication drives its ladders with read the bits of
        the multiplier with shifts, masks and divisions.  Handing those a value
        that merely converts to an integer -- the decimal digits of a string,
        or a float truncated towards zero -- would multiply by a number the
        caller never asked for, and handing them one that doesn't convert at
        all would surface as whichever error the first arithmetic operation
        happens to raise, which differs between the integer implementations
        this module can use.  Requiring the multiplier to implement
        ``__index__()``, the protocol by which Python asks a number for its
        lossless integer value, rejects both cases with one and the same
        exception: `int`, `bool` and the ``mpz`` of both gmpy releases provide
        it, while floats, strings, bytes and complex numbers do not.

        `operator.index()` is what asks, rather than a direct call of the
        method, because it also refuses a ``__index__()`` that answers with
        something that is not an integer.  Calling the method directly would
        return whatever it handed back, and a value that merely looks like a
        number to the arithmetic that follows -- the string ``"3"`` reduces
        modulo an order to three -- would again multiply the point by a number
        the caller never asked for, which is the very case this helper exists
        to prevent.

        Nothing here reads the value of the multiplier, only its type, so this
        step cannot tell one integer from another and cannot put a multiplier's
        value into the work a multiplication performs.

        The value is returned as a plain `int` because gmp object creation has
        cumulatively higher overhead than the speedup we get from calculating
        the recodings using gmp, the same reason `mul_add()` coerces its own
        multipliers.

        :param mult: the multiplier a caller passed to a multiplication

        :raises TypeError: if the multiplier is not an integer, or offers a
            ``__index__()`` that does not answer with one

        :return: the multiplier as a plain integer
        :rtype: int
        """
        try:
            return operator.index(mult)
        except TypeError:
            # re-raised rather than propagated so that the message names the
            # type the caller passed; the one `operator.index()` raises names
            # it only when the multiplier offers no `__index__()` at all
            raise TypeError(
                "multiplier must be an integer, not %s" % type(mult).__name__
            )

    @staticmethod
    def _fixed_window(order):
        """
        Digit width the fixed length recoding can use for a point of `order`.

        Returns ``_MUL_WINDOW`` when the order can carry it and zero when the
        order cannot be used at all, in which case `_fixed_ladder_usable()` is
        false and the multiplication falls back to the non-adjacent form
        recoding of `_naf()`.  There is nothing in between, and deliberately
        so.  A narrower width would in fact admit an order this one refuses,
        its largest digit being smaller, but reaching for a second width to
        rescue such an order would make the width a point is recoded at a
        property of that point's order, which is a property the caller of a
        public constructor chooses; one width for every point that has one
        keeps the recoding a function of nothing but the order it is sized
        from.

        Two properties of the order are needed, and neither can be assumed
        because the point constructors are public and accept an arbitrary
        value.  Both are consequences of the mechanism rather than thresholds
        chosen here, and every one of the twenty six curves this library
        registers satisfies both, each declaring an odd generator order of a
        hundred and ten bits or more:

        * it must be **known and odd**.  `_canonical_scalar()` adds a multiple
          of the order to make a multiplier odd, which only works when the
          order itself is odd, and `_fixed_digits()` requires an odd input.
          An even order cannot be worked around: no odd number is congruent
          to an even residue modulo an even order, so there is no canonical
          value to recode in the first place.  Worse, the order of
          ``2 ** (j * window)`` times the point collapses to
          ``order // 2 ** min(v, j * window)`` for ``v``
          the number of times two divides the order, so a partial result of the
          ladder can reach the point at infinity part way through and the
          sequence of addition formulas becomes a function of the multiplier
          again.  ECDSA and SEC 1 both require the generator order to be prime,
          so no conforming parameter set is affected; a caller who builds a
          point of even order by hand keeps the behaviour of releases up to
          0.19.1 for it.
        * it must be **larger than the largest digit** the recoding can
          produce, which is ``2 ** window - 1``.  The ladders answer a digit
          with the odd multiple of the point that it names, and where the order
          is no larger than that largest digit one of those odd multiples is a
          multiple of the order, and so the point at infinity -- which the
          affine entries of a multiplication table cannot hold at all, see
          `PointJacobi._maybe_precompute()`.  Nothing is given up by leaving
          such a point on the fall-back, either: a group of at most ``2 **
          window - 1`` points hands over any multiplier to a search of at most
          that many tries, so how long a multiplication of one takes tells an
          attacker nothing they could not have had for free.

        :param order: order of the point, or a false value when it is unknown

        :return: the digit width to use, or zero
        :rtype: int
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
        carry.  A point whose order it cannot -- one that reports no order, one
        of even order, or one of a group narrower than the widest digit the
        recoding can produce -- falls back to the non-adjacent form recoding of
        `_naf()`: correct, just not hiding the width of the multiplier.

        Every curve this library registers has an odd generator order wide
        enough to carry the recoding, so every point built by multiplying one
        of their generators -- which is every point `ecdsa.keys.SigningKey`
        and `ecdsa.ecdsa` derive -- takes the fixed work path.  A point that
        reaches the fall-back is one whose order the caller did not supply: the
        public point encodings carry no order, so a point decoded by
        `ecdsa.keys.VerifyingKey.from_string()` and its DER and PEM
        counterparts reports none, and one built through the public
        constructors of this module reports whatever the caller passed.  Such a
        point is left on the fall-back rather than rejected, because rejecting
        it would withdraw a documented way of building a point.
        """
        return bool(cls._fixed_window(order))

    @staticmethod
    def _canonical_scalar(mult, order):
        """
        Bring a multiplier to the form the fixed length recoding expects.

        Returns an odd number congruent to ``mult`` modulo ``order`` and lying
        in the interval that starts at ``order`` and is two orders wide,
        whatever ``mult`` was.  Multiplying by the returned value gives the
        same point as multiplying by ``mult``, because ``order`` times a point
        of that order is the point at infinity, and thus adding a multiple of
        the order to a multiplier does not change the result.

        Two properties are what the ladders need of it, and both hold for every
        residue of every order they accept:

        * it is **odd**, which `_fixed_digits()` requires of its input, and
          which is why `_fixed_window()` refuses an even order: the residue is
          made odd by adding one order to it where it is even and two where it
          is odd, and only an odd order can change the parity of a value that
          way.  Selecting the multiple by index rather than by branch is what
          keeps the work of this function the same for either parity;
        * it is **smaller than** ``2 ** (bit_length(order) + 2)``, since three
          orders are, which is what lets `_fixed_digit_count()` size a recoding
          of it from the (public) order alone.  That is the whole of what makes
          the number of point operations of a multiplication a function of the
          curve: no shorter multiplier is recoded into fewer digits, and no
          digit is ever zero, so none is ever skipped.

        What this deliberately does **not** do is give every multiplier the
        same bit length: three orders reach two bits above the order for some
        curves and one for others, so the returned value is
        ``bit_length(order)`` to ``bit_length(order) + 2`` bits wide depending
        on the residue.  Python integers cost what their width costs, so a
        per-operation cost that varies by a bit or two of operand width
        remains, on top of the variation `ellipticcurve` already has from
        skipping the reduction modulo the field prime where that is faster.
        What is fixed is the number of point operations, which is the carrier
        CVE-2024-23342 was reported on; the residue of a per-operation signal
        is disclosed in ``SECURITY.md`` rather than claimed away.

        Neither does it rule out every degenerate addition: the least
        significant digit of the recoding is read off the low bits of the
        returned value, and where that digit ``d`` satisfies ``2 * d ==
        residue`` the last addition of the ladder is handed two equal operands
        and answers with the doubling formula.  Writing ``m`` for
        ``2 ** (window + 1)``, that happens for the residue ``2 * d`` when
        ``order`` is congruent to ``2 ** window - d`` modulo ``m`` and for the
        residue ``order - 2 * d`` when ``3 * order`` is congruent to
        ``2 ** window + d`` modulo ``m``, over the odd ``d`` below
        ``2 ** window``; at most two residues of any order satisfy either, and
        for some -- SECP160r1 among the curves this library registers -- none
        does.  `PointJacobi._mul_precompute()` records what that costs.

        The order is coerced to a plain integer first, so that a point whose
        order is a gmp object still answers with an ordinary one -- the same
        reason `mul_add()` coerces its own multipliers, gmp object creation
        costing more here than the arithmetic it speeds up.

        :param mult: the multiplier to normalise
        :param order: order of the point, which must be odd

        :return: an odd value congruent to `mult` modulo `order`
        :rtype: int
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

        A canonical multiplier (see `_canonical_scalar()`) is below three times
        the order, and therefore below ``2 ** (bit_length(order) + 2)``,
        whatever the multiplier it was derived from was.  As many whole windows
        as it takes to cover those bits are always both enough to hold every
        canonical multiplier of this order and no more than the widest of them
        needs, so the count is a function of the (public) order alone -- which
        is what makes the number of point operations of a multiplication one
        too.
        """
        return (bit_length(order) + 2 + window - 1) // window

    @classmethod
    def _fixed_table_length(cls, order, window):
        """
        Number of entries the multiplication table of `order` holds.

        Every digit position holds the ``2 ** (window - 1)`` odd multiples a
        whole window reaches, so that a digit of any magnitude the recoding can
        produce is answered by one entry of the position it belongs to and no
        position needs a layout of its own.  See
        `PointJacobi._maybe_precompute()`, which builds exactly this many, and
        `PointJacobi.__setstate__()`, which uses this to tell a table it can
        index from one it cannot.  On NIST256p that is 65 positions of 8
        entries each, 520 in total.
        """
        return cls._fixed_digit_count(order, window) * (1 << (window - 1))

    @classmethod
    def _fixed_table_shaped(cls, table, order, arity):
        """
        Whether `table` is shaped like a table this code can index.

        A restored multiplication table (see `PointJacobi.__setstate__()`) is
        usable only if this layout would have built one of the same shape for
        the same order: as many entries as `_fixed_table_length()`, each of
        `arity` coordinates.  An order the fixed length recoding cannot use
        indexes no table at all, so nothing is shaped for it.

        This is a test of shape and not of contents: a table of the right shape
        holding the wrong multiples is accepted, exactly as releases up to
        0.19.1 accepted any table at all.  Checking the multiples would mean
        computing them, which is the work the table exists to avoid.
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

        Returns exactly ``count`` digits, least significant one first.  Every
        digit is odd, and therefore never zero, and its absolute value is
        smaller than ``2 ** window``.  A ladder driven by such a sequence
        performs exactly one point addition per digit, so the number of
        additions depends only on ``count`` and not on ``mult``.

        ``mult`` must be odd and smaller than ``2 ** (count * window)``;
        `_canonical_scalar()` and `_fixed_digit_count()` together guarantee
        both.  This is the regular recoding of Joye and Tunstall; with
        ``window`` equal to 1 it degenerates into a signed binary expansion
        with digits taken from ``{-1, 1}``.
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

        The table holds, for every digit position `_fixed_digits()` emits, the
        odd multiples of this point that a digit in that position can select,
        so `_mul_precompute()` can answer any digit with a single addition of
        one affine entry.  Writing ``digits`` for `_fixed_digit_count()`, it
        holds the ``digits * 2 ** (window - 1)`` entries
        `_fixed_table_length()` names.  Building them costs ``window * (digits
        - 1) + 1`` point doublings -- one for the step between consecutive odd
        multiples of each position's base, and ``window - 1`` more to carry
        that step to the base of the next position -- and ``digits * (2 **
        (window - 1) - 1)`` point additions, the first entry of a position
        being its base.  Nothing follows the most significant position, so its
        base is not advanced.
        On NIST256p that is 520 entries for 257 doublings and 455 additions,
        and on NIST521p 1048 entries for 521 doublings and 917 additions.
        Every later multiplication reads the finished table and performs no
        doubling at all, which is what leaves its cost a function of the curve
        and of nothing else.
        """
        if not self.__generator or self.__precompute:
            return

        order = self.__order
        assert order
        window = self._fixed_window(order)
        if not window:
            # An order that the fixed length recoding cannot use also cannot
            # index this table, and an order small enough to divide one of the
            # odd multiples below would put the point at infinity in it, which
            # the two coordinates stored per entry cannot represent.  Leaving
            # the table empty sends such points through `__mul__`'s table-less
            # paths, which handle every order.
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
        # The multiplication table is a rebuildable cache, so a restored one is
        # kept only when this layout could have written it and would index it
        # the same way: as many entries as `_fixed_table_length()`, each a pair
        # of coordinates, for an order the fixed length recoding can use.  A
        # table of any other shape -- one written by a release whose table held
        # the successive doublings of this point rather than the odd multiples
        # of each digit position, one absent from the state altogether, one
        # truncated or otherwise malformed -- would be indexed with a layout it
        # doesn't have, reading the wrong entries or running off the end of the
        # list, so it is dropped here and `_maybe_precompute()` builds the
        # right one on first use.  Dropping it is silent and raises nothing: an
        # unrecognised cache is not a broken pickle, and the point it describes
        # is restored in full by the assignment above.
        #
        # That guards this direction only.  `__getstate__()` above is the plain
        # instance dictionary that releases up to 0.19.1 wrote, table and all,
        # so a state written here and read by one of those releases hands it a
        # table of this layout to index as the successive doublings of the
        # point -- and it has no test to notice, so it would answer with a
        # wrong point rather than an error.  That residual is accepted and
        # recorded in `SECURITY.md`; it is inherent to changing the layout of a
        # cache that a serialised point has always carried, and the format
        # itself is deliberately left as it was rather than narrowed, so that a
        # state of this class stays the plain instance dictionary every release
        # of this library has read and written.
        #
        # Both values are read from the state rather than from the instance, so
        # that a state missing either key is answered like any other unusable
        # one instead of raising something no release ever raised here.
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

        A single modular inversion is used for the whole list, by inverting
        the product of all the Z coordinates and then recovering each
        individual inverse from it with two multiplications.  Modular
        inversion is by far the most expensive field operation used here, so
        inverting once instead of once per entry is what keeps the table this
        builds affordable for `_mul_fixed()`, which rebuilds it on every call.

        A zero Z, the representation of the point at infinity, is counted as
        one in that product and comes back out as all-zero coordinates, so the
        point at infinity is preserved.  That case is not hypothetical: the
        table of odd multiples built by `_mul_fixed()` runs past the order of a
        low order point, so the point at infinity does appear in it.  Letting a
        zero into the product would leave every entry with zero coordinates,
        as `numbertheory.inverse_mod()` maps zero to zero.
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
        Because every digit of the recoding is non-zero, this performs exactly
        one point addition per digit and no point doublings at all, so the
        number of point operations is a function of the curve order only.  The
        sign of a digit costs the same as well: both polarities of the selected
        table entry are derived for every digit and the answer is picked out by
        index, so the number of field wide negations follows the number of
        digits rather than the number of negative ones among them.  The
        accumulator starts out as the point at infinity and every table entry
        is affine, which means `_add()` takes its "Z1 is zero" branch on the
        first digit, `_add_with_z_1()` on the second -- there both Z are one --
        and `_add_with_z2_1()` on every one after that, a sequence that
        likewise doesn't depend on the multiplier.  `mul_add()` hands its work
        to `__mul__()` when both of its points carry a table, so a verification
        against a `ecdsa.keys.VerifyingKey` on which `precompute()` was called
        runs this method too, with multipliers derived from the signature and
        therefore public.

        The digits are consumed most significant one first, which is what makes
        that claim about the sequence of branches true.  Write the recoding of
        the canonical multiplier ``K`` as ``K = sum(d[i] * 2**(i * window))``;
        the recurrence that produces it, see `_fixed_digits()`, also defines
        the remainders ``K[j] = sum(d[i] * 2**((i - j) * window))`` over
        ``i >= j``, so ``K[0] == K``, ``K[j] = d[j] + 2**window * K[j + 1]``,
        and the accumulator held while the digit of position ``j`` is being
        added is exactly ``2**(j * window) * K[j + 1] * 2**window``, that is
        ``(K[j] - d[j])`` times this point.  Two properties follow, and both
        are needed:

        * every ``K[j]`` with ``j`` above zero is odd, positive and no larger
          than ``(K - 1) // 2**window + 1``, each step of the recurrence
          replacing a value with an odd one no larger than that fraction of it.
          A canonical multiplier is below three orders, and three orders over
          ``2**window`` plus one is below one order for every order
          `_fixed_window()` accepts -- it accepts none that is not larger than
          ``2**window - 1``.  So every such ``K[j]`` lies strictly between zero
          and the order, is therefore non-zero modulo the order, and the
          accumulator is the point at infinity only before the first addition;
        * the accumulator equals its addend only where ``K[j]`` is congruent to
          ``2 * d[j]`` modulo the order, which is where the addition formula
          answers with ``_double_with_z_1()`` in place of its own.  For ``j``
          above zero that cannot happen: ``K[j]`` is odd while ``2 * d[j]`` is
          even, and by the bound above the two differ by less than the order,
          so they cannot be congruent without being equal.  For ``j`` equal to
          zero it can, and at most two residues of any order reach it -- none
          at all for some, see the closed form in `_canonical_scalar()`'s note
          on what it does not do.  That is a disclosed residual and not a hole
          in the count: it is at most two multipliers out of the order, which
          for a 256 bit curve is around two to the power of minus two hundred
          and fifty five of them, it is one field operation cheaper rather than
          one point operation more, and it leaves the number of calls to both
          of the dispatchers above the same, the fall-back being entered inside
          the addition formula and answered by ``_double_with_z_1()`` directly.
          Which formula that is follows the digit count and not the multiplier:
          ``_add_with_z2_1()`` for a recoding of three digits or more, and
          ``_add_with_z_1()`` where it is two, the accumulator then still
          carrying the ``z`` of one the first digit gave it.  Both compare
          their operands after reducing modulo the field prime, which is why
          the negation applied to a table entry below is reduced too.
          ``SECURITY.md`` records the residual;
        * the accumulator equals the negation of its addend only if ``K[j]`` is
          congruent to zero modulo the order, which by the bound above again
          leaves only ``j`` equal to zero, that is a multiplier that is a
          multiple of the order.  There the sum being the point at infinity is
          the correct answer, and it doesn't perturb the sequence of branches:
          opposite points make the ``H`` of the addition formula zero but leave
          its ``r`` non-zero, so the "both zero" short circuit that would call
          the doubling formula instead is not taken.  Such a multiplier is
          public by nature -- it cannot be a nonce, as
          `ecdsa.ecdsa.Private_key.sign()` rejects those.

        Consuming the digits the other way round provides none of that: the
        partial sums are then arbitrary residues and do hit the point at
        infinity for some multipliers -- ``2**bit_length(order) - order`` is
        one of them -- which shows up as a second use of the "Z1 is zero"
        branch and so as a difference in run time that depends on the
        multiplier.
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
            # order, and the sign of the digit is applied by negating the Y
            # coordinate of the selected one.  Both polarities are derived for
            # every digit and one of them is picked out by index, so the
            # negation of a coordinate as wide as the field is paid once per
            # digit whatever the signs of the digits are -- an `if` here would
            # pay it only on the negative ones and leave the count of them,
            # which follows the multiplier, in the run time.
            #
            # The negation is reduced modulo the field prime rather than left
            # bare.  `_add_with_z_1()`, which this reaches on the second digit,
            # reads two operands as equal by comparing the raw differences of
            # their coordinates, so a bare negation would hide that equality
            # from it and it would answer the correct point of a group whose
            # recoding is two digits wide with the point at infinity instead.
            # Every other addition formula reduces before comparing, so this
            # costs one reduction per digit and changes no result.
            X2, Y2 = precompute[offset + ((abs(dig) - 1) >> 1)]
            X3, Y3, Z3 = _add(X3, Y3, Z3, X2, (Y2, -Y2 % p)[dig < 0], 1, p)
            offset -= odd_multiples

        if not Z3:
            return INFINITY
        return PointJacobi(self.__curve, X3, Y3, Z3, self.__order)

    def _mul_fixed(self, other):
        """
        Multiply point by integer without a precomputation table.

        This is the path taken by a point that is not a curve generator but
        does know its order, most importantly by an ECDH exchange, where the
        multiplier is the long term private key rather than a single-use nonce.
        `other` must be a canonical multiplier, see `_canonical_scalar()`,
        which also means the caller must have established that the order can be
        used; a point whose order cannot is handled by `__mul__()` directly.

        Performs ``(count - 1) * window`` point doublings and ``count`` point
        additions, with ``count`` derived from the curve order, plus the
        constant one doubling and ``2 ** (window - 1) - 1`` additions that
        build the table of odd multiples of this point.  None of those counts
        depends on the multiplier.  For a 256 bit order and the window this
        module uses that is 257 doublings and 72 additions, every time.
        """
        p, a = self.__curve.p(), self.__curve.a()
        order = self.__order
        window = self._fixed_window(order)
        _double = self._double
        _add = self._add
        digits = self._fixed_digits(
            other, self._fixed_digit_count(order, window), window
        )

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

        if not Z3:
            return INFINITY

        return PointJacobi(self.__curve, X3, Y3, Z3, self.__order)

    def __mul__(self, other):
        """Multiply point by an integer."""
        # This first test reads this point, not the multiplier: the point at
        # infinity stays where it is whatever it is multiplied by, and no
        # multiplier can be told anything about from the answer.
        if not self.__coords[1]:
            return INFINITY
        # Normalise the multiplier to a plain integer before it is used for
        # anything at all, this method's own choice of ladder included, so that
        # every path below reads bits of an integer and a value that is not one
        # is refused the same way on all of them.  This reads the type of the
        # multiplier and never its value; see `_integer_multiplier()`.
        other = self._integer_multiplier(other)
        order = self.__order
        fixed = self._fixed_ladder_usable(order)
        if fixed:
            # Normalise the multiplier before ANY choice is made from its
            # value, the shortcuts for a multiplier of zero or of one included.
            # Such a shortcut is precisely the short circuit CVE-2024-23342 is
            # about: it would answer those two multipliers in no point
            # operations at all where every other one costs the full fixed
            # number, and a nonce of one is not hypothetical --
            # `sign_number()` accepts any value from one up.  Normalised, both
            # of them run the same ladder as every other multiplier and cost
            # exactly the same, and what a caller asking for either gets back
            # is still what releases up to 0.19.1 gave them: the point at
            # infinity, and this very object.  The one for a multiplier of one
            # is picked out at the end of this method, after the work.
            multiplier = self._canonical_scalar(other, order)
        else:
            # An order the fixed length recoding cannot use, or none at all.
            # There is nothing to normalise a multiplier against, so the two
            # shortcuts below cannot make the work depend on a multiplier any
            # more than the ladder that follows them already does, and they
            # keep returning what releases up to 0.19.1 returned: the point at
            # infinity, and this very object -- with the order it knows, its
            # generator flag and its multiplication table -- rather than an
            # equal but freshly built point.  No path of this library that
            # multiplies by a secret arrives here, see the comment further
            # down.
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
            # releases up to 0.19.1 answered it, but only once the ladder above
            # has performed the same work every other multiplier pays for: the
            # answer is picked out by index rather than by a branch that skips
            # that work, so no multiplier is cheaper than any other.  The
            # fall-back path below returned the same answer further up, ahead
            # of a ladder whose work follows the multiplier anyway.
            return (product, self)[other == 1]

        # The order of this point is unknown or unusable, so the width of the
        # multiplier cannot be normalised.  The number of iterations of the
        # ladder below tracks the bit length of the multiplier -- a
        # non-adjacent form can carry one digit further than that length -- and
        # the number of point operations follows the multiplier with it, so
        # this ladder is not side channel hardened, and a caller that builds a
        # point without a usable order through the public constructors of this
        # module and multiplies it here gets that.
        #
        # What is claimed is narrower.  Every registered curve declares an
        # order the fixed length recoding can use, so signing, key generation
        # and EdDSA -- which all multiply a generator built with its order --
        # never arrive here.  An ECDH exchange does when the remote public
        # point was decoded from an encoding: those encodings carry no order
        # and nothing attaches one afterwards, so the multiplier this ladder is
        # driven by is the long term private key and the number of iterations
        # follows its bit length.  A remote public key handed over as a
        # `ecdsa.keys.VerifyingKey` this process derived from a
        # `ecdsa.keys.SigningKey` does carry the order and takes the recoded
        # path instead.  That residual exposure is recorded in `SECURITY.md`; a
        # point a caller constructs without an order, or with one the recoding
        # cannot use, keeps this ladder too.
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
        # This first test reads this point and not the multiplier: the point at
        # infinity stays where it is whatever it is multiplied by, and releases
        # up to 0.19.1 answered it before looking at the multiplier at all, so
        # it comes ahead of the normalising step below as well.
        if self == INFINITY:
            return INFINITY
        # Normalise the multiplier to a plain integer before it is used for
        # anything, this method's own choice of ladder included; see
        # `PointJacobi.__mul__()` and `_integer_multiplier()`.
        other = self._integer_multiplier(other)

        # The X9.62 D.3.2 ladder further down performs a number of point
        # operations that follows the multiplier, and each of those operations
        # dispatches on the relation between its operands, so it cannot hide a
        # secret multiplier.  Points whose order supports it therefore hand the
        # work to the Jacobi coordinate implementation, which performs a fixed
        # number of operations in a fixed sequence, and convert the result
        # back.  Nothing is answered ahead of that hand-off -- not a multiplier
        # of zero, not one of one, not a multiple of the order and not a
        # negative one -- because every such shortcut would answer its
        # multiplier in fewer point operations than the ladder spends on all
        # the others, which is the short circuit CVE-2024-23342 is about.
        order = self.__order
        if self._fixed_ladder_usable(order):
            product = (
                PointJacobi(self.__curve, self.__x, self.__y, 1, order) * other
            )
            if product == INFINITY:
                return INFINITY
            # For every multiplier but one the order is deliberately not
            # carried over, matching what `__add__()` and `double()` return and
            # so what releases up to 0.19.1 returned here.  A multiplier of one
            # those releases answered with this very object, order and all, and
            # so does this: the answer is picked out by index once the ladder
            # above has performed the work every other multiplier pays for,
            # rather than by a branch that skips it.
            return (Point(self.__curve, product.x(), product.y()), self)[
                other == 1
            ]

        # Reached for an order the fixed length recoding cannot use and for no
        # order at all.  Defect #5 of the plan -- a ladder whose length follows
        # the multiplier -- is not remediated here but avoided above, and this
        # ladder is left exactly as releases up to 0.19.1 wrote it, down to
        # which shortcut answers which multiplier, because a point that reaches
        # it has no order to normalise a multiplier against and so nothing to
        # gain from a rewrite:
        #
        #  * a point that reports no order cannot have a multiplier reduced
        #    against one, so there is nothing for the recoding to be given;
        #  * an even order admits no odd congruent multiplier at all, so the
        #    recoding `_fixed_digits()` performs cannot represent one;
        #  * an order no larger than the largest digit the recoding emits is a
        #    group in which a table entry would be the point at infinity, which
        #    affine coordinates cannot hold -- and a group that small hands
        #    over any multiplier to a search of at most that many tries anyway,
        #    so how long a multiplication takes tells an attacker nothing they
        #    could not have had for free.  See `_fixed_window()`, where both
        #    bounds are decided;
        #  * every curve this library registers declares an order the recoding
        #    can use, so no signature, key generation or ECDH operation of this
        #    library arrives here for want of one.

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

        Same layout and the same number of entries as the table
        `PointJacobi._maybe_precompute()` builds, and the same number of point
        additions and point doublings to build them, except that entries are
        ``(x, y, x * y % p)`` triples rather than pairs, as the addition
        formula of this curve type consumes that product.  On Ed25519 that is
        512 entries for 253 doublings and 448 additions, and on Ed448 896
        entries for 445 doublings and 784 additions.
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
        # `PointJacobi.__setstate__()`, which carries the full reasoning
        # including the residual this guards only one direction of, with the
        # three coordinates an entry of this curve type holds in place of the
        # two of that one.
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
        Because every digit of the recoding is non-zero, this performs exactly
        one point addition per digit and no point doublings at all, so the
        number of point operations is a function of the curve order only.  The
        sign of a digit costs the same as well: both polarities of the selected
        table entry are derived for every digit and the answer is picked out by
        index, so the number of field wide negations -- two per digit here,
        since the product of the affine coordinates is negated along with the x
        one -- follows the number of digits rather than the number of negative
        ones among them.

        The digits are consumed most significant one first for the reason
        spelled out in `PointJacobi._mul_precompute()`: it is what keeps every
        accumulator away from its addend, and the addition formula of this
        curve type falls back to the doubling formula when handed two operands
        with the same product of affine coordinates.  For points of the odd
        order subgroup that only happens when the operands are equal, since the
        at most four points that share such a product differ from each other by
        a point of even order.  The one place that argument leaves open is the
        least significant digit, and at most two residues of any order do reach
        it -- one of Ed25519's and one of Ed448's, by the closed form in
        `_canonical_scalar()`.  Unlike the Weierstrass ladder this one pays a
        counted point doubling for that, so for those residues the doubling
        count of a multiplication is one rather than zero; ``SECURITY.md``
        records the residual, whose share of the multipliers of either curve is
        below two to the power of minus two hundred and fifty.
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
            # order, and the sign of the digit is applied by negating the x
            # coordinate (and with it the x*y product) of the selected one.
            # Both polarities are derived for every digit and one of them is
            # picked out by index, so the two negations of coordinates as wide
            # as the field are paid once per digit whatever the signs of the
            # digits are; an `if` here would pay them only on the negative
            # ones and leave the count of those in the run time.
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

        This is the path taken by points of a known order that are not marked
        as curve generators.  `other` must be a canonical multiplier, see
        `_canonical_scalar()`.

        Performs ``count * window`` point doublings and ``count`` point
        additions, with ``count`` derived from the curve order, plus the
        constant one doubling and ``2 ** (window - 1) - 1`` additions that
        build the table of odd multiples of this point.  None of those counts
        depends on the multiplier, with the single exception
        `_mul_precompute()` records: the at most two residues of an order whose
        least significant digit leaves the last addition of the ladder with two
        equal operands pay one counted doubling more than every other
        multiplier, the addition formula of this curve type answering equal
        operands with the doubling one.
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
        # normalised to a plain integer before it is used for anything, this
        # method's own choice of ladder included; see `PointJacobi.__mul__()`
        # and `_integer_multiplier()`
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
            # releases up to 0.19.1 answered it, but only once the ladder above
            # has performed the same work every other multiplier pays for; see
            # `PointJacobi.__mul__()`.
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
