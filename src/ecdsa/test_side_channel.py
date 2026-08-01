"""
Deterministic regression tests for the nonce bit length side channel.

CVE-2024-23342, GHSA-wj6h-64fc-37mp and PYSEC-2026-1325 report a Minerva class
attack against this library: the time `ecdsa.keys.SigningKey.sign_digest()`
took was a function of the secret per signature nonce, so an attacker able to
time enough signatures learns a few high order bits of each nonce and
assembles those partial leaks into a hidden number problem lattice that
recovers the long term private key.  Key generation and ECDH key agreement
multiply by the private key over the same code, and were affected the same
way.  Signature verification, which handles only values anyone holding the
signature can derive, was not.

What carried the leak was the number of elliptic curve point operations a
multiplication performed.  The number of point additions equalled the Hamming
weight of the non adjacent form of the multiplier and the number of iterations
of the table less ladder tracked its bit length, so both followed the nonce;
and the bit length padding `ecdsa.ecdsa.Private_key.sign()` applied to hide the
nonce was annihilated by the reduction the multiplication then performed on the
padded value, which is the "nonce unpadding" failure the side channel analysis
of Mozilla's NSS (arXiv:2008.06004) describes.  The countermeasure normalises
the multiplier inside the arithmetic layer and recodes it into a fixed length
sequence of digits none of which is zero, so that the number of point
operations follows the curve order -- which is public -- and nothing else.

That fixed number of operations is what a point whose order the recoding can
use performs, which is every point the registered curves and the secret bearing
entry points of this library reach, and such a point performs it for every
multiplier it accepts, zero and one included, so that no value a caller can
hand one of those multiplications is answered without the work.  A point that
carries no usable order keeps the older ladder, whose count follows the
multiplier; `TestEdgeCasePreservation` pins what that ladder answers as a
compatibility behaviour and not as a hardened one.  A multiplier that is not an
integer has no bits for the recoding to read and is refused, uniformly and
before either ladder is chosen; `TestMultiplierNormalisation` is where that is
asserted, and it is the one caller visible change in this file.

These tests therefore assert **point operation counts**, never the wall clock.
Both reasons are deliberate: the operation count is the carrier the leak
travelled on, so counting it measures that carrier directly rather than
standing in for it; and a wall clock assertion in a unit suite would be
inherently flaky, would have no threshold that holds across machines, and is
re-run hundreds of times over by the mutation testing gate.  The statistical
wall clock measurement of the signal that remains lives in the
`minerva_probe.py` script at the root of this repository, and is deliberately
kept out of this suite.

Nothing here claims that an operation of this library takes the same amount of
time whatever its inputs are, and nothing could: Python integers cost time
proportional to their magnitude, and `ecdsa.ellipticcurve` deliberately skips
the reduction modulo the field prime where that is faster, so the width of the
field operands still varies.  What these tests pin is the number of point
operations, and the shape of the recodings that fixes it.

Most of what is asserted here fails against the arithmetic of the unmodified
0.19.1+2.g55aca78 tree, which is what makes these tests evidence of a defect
rather than a description of the code that replaced it.  The class named for
signature transparency is the exception and asserts, every test of it, what
the countermeasure had to leave exactly as it was; the one named for edge case
preservation is very nearly that too, in twelve of its sixteen tests, and what
the few remaining ones are for is named below.  Every count in the paragraphs
that follow was measured by
copying this file -- and nothing else -- into a checkout of 55aca78 and
running `pytest src/ecdsa/test_side_channel.py` against it, so any reader can
take the measurement again rather than take these numbers on trust.

* `TestPointAdditionCountInvariance` fails in every one of its twelve tests.
  Walked with the helpers of this module -- the six bit widths
  `stratified_widths()` returns for a curve and the eight multipliers of each
  that `SCALARS_PER_WIDTH` asks for outside the fast selection -- the number
  of point additions of a multiplication took 23 to 31 distinct values per
  curve there, spanning 52 to 92 additions on NIST256p, 19 to 57 on SECP160r1
  and 44 to 94 on Ed25519, where each of those curves now answers every one of
  those multipliers with a single count.  One of the twelve takes a
  multiplication through a pickle, and it fails there for a second reason as
  well as that one: the table a release up to 0.19.1 writes into its state is
  of another length and is indexed as the successive doublings of the point, so
  a restored point costs there whatever an unserialised one costs, which is to
  say a count that follows the multiplier.
* `TestSignedDigitSymmetry` fails in five of its six tests, each of the five
  for want of the recoding whose digits it counts the coordinate negations of.
  What it pins is the half of the fixed work ladder a count of point
  operations does not reach: a negative digit and a positive one have to cost
  the same negation, or the number of negations would follow the multiplier
  even where the number of point operations no longer does.  The test that
  passes there guards the counter itself and needs nothing of the recoding.
* `TestNonceUnpaddingRegression` fails by construction in six of its ten
  tests, most plainly on SECP160r1, the registered curve whose order left the
  old padding useless for all but a vanishing fraction of the nonces.  The four
  that pass there are meant to: they work out arithmetically what the old
  padding and the old reduction did to a nonce without asking either ladder to
  do anything, so they describe the defect on both trees alike.
* `TestEdwardsRawScalarRegression` fails in two of its four tests.  The
  padding the class above is about was applied in `Private_key.sign()` and
  nowhere else, and EdDSA never went through it, so what the Edwards ladder
  had was a leak of its own rather than a cancelled countermeasure and this
  class is where it is stated: `ecdsa.eddsa.PrivateKey.sign()` multiplies the
  generator by a whole hash, which those releases reduced modulo twice the
  order and then spent a number of point operations on that followed the width
  and the non adjacent form of what came out.  Both of those two failures are
  an `AttributeError` for an internal the unmodified tree does not define, the
  digit width in one and the normalisation in the other, which is a weaker kind
  of evidence than an assertion that fails, so the leak is stated in the form
  that needs neither: the eight multipliers of 512, 253, 128 and 64 bits that
  the addition count test of that class drives cost that tree between 22 and 87
  point additions, a spread of 65 over the widths a hash covers, where every one
  of them now costs 64.  The two tests that pass there are what makes the class
  evidence of that rather than a description of the curves: one is the width of
  the multiplier EdDSA hands over, measured through the signing path itself,
  and the other is the spread the old reduction left of it, and both hold on
  either tree.
* `TestFixedDigitRecoding` and `TestCanonicalScalar` fail with an
  `AttributeError`: the recoding they describe did not exist.  One test of
  each survives there, and neither touches it: the one that asserts the non
  adjacent form the verification path still uses is where it always was, and
  the one that asserts every registered curve has an odd order.
* `TestNarrowOrderHardening` fails in twelve of its fifteen tests, all twelve
  for want of the recoding the narrow groups it builds are driven through.
  Those groups are of seventeen points upwards, between three and fourteen
  orders of magnitude narrower than the narrowest curve this library registers,
  so they are where the leak is widest relative to the group and they are small
  enough to be checked for every multiplier there is.  Of the three that pass,
  two check that those groups -- the short Weierstrass ones and the twisted
  Edwards ones -- are the groups they claim to be, and the third measures what
  they cost before the countermeasure, so it describes the defect on both trees
  alike.
* `TestMultiplierNormalisation` fails in nine of its twelve tests, and it is
  the one class here whose subject is a change a caller can observe.  Six of
  the nine are an `AttributeError` for the normalising step itself, which the
  unmodified tree does not define; the other three assert the refusal through
  the multiplication operator, where that tree answered a float of one with the
  point, read a `None` as a zero, and refused the rest by way of whichever
  arithmetic operation reached them first.  Of the three that pass, one is the
  half of the refusal that tree did draw -- a value whose ``__index__()``
  answers with a string was refused there too, by the reduction modulo the
  order -- one is the point at infinity, answered ahead of the multiplier on
  both trees, and the third is why the change costs this library's own callers
  nothing: every multiplier the signing, key generation, ECDH and EdDSA paths
  form is an integer, asserted by driving all four rather than argued.
* `TestBlindedInversion` fails in nine of its eleven tests, six of them with an
  `AttributeError`: blinding the inversion of the nonce is the one thing
  signing does now that it did not do before, so the signing module of that
  tree reaches for no entropy source and the name those six stand in for -- its
  `randrange` -- is not there to be found.  Of the three that reach their
  assertions, two are the countermeasure itself: signing did not read the
  operating system at all where it now reads it at least once per signature, and
  eight repetitions of one signature handed the inversion one operand where they
  now hand it eight.  The third is the residue that is left deliberately: on that
  tree a nonce of one or of two left the point in a form whose first coordinate
  could be read without inverting anything modulo the field prime, so signing
  inverted once for those two nonces and twice for the rest.  The two that pass
  describe a collaborator rather than the library -- what `util.randrange()`
  can answer with, and that a factor drawn from it blinds and unblinds on every
  curve -- so they hold on both trees and are what makes the rejection branch
  the tests above drive reachable only on a composite order.
* One class in this file asserts a change a caller can observe, and only one:
  `TestMultiplierNormalisation`, where a multiplier that is not an integer is
  refused rather than truncated or read as a zero.  It is called out here
  because the rest of the file deliberately does not, and because that refusal
  is a deliberate part of the change -- the guard that answered a multiplier of
  one had to move behind the normalising step, or a nonce of one would never
  reach a ladder.  Of the remaining classes, the tests that name an internal --
  the recorded and recoded orders of `TestECDHKeyAgreement`, the drawn factor
  and the blinded operand of `TestBlindedInversion`, the digit widths and table
  shapes elsewhere -- name it as an internal; everything else asserts either a
  cost that no longer follows a secret, an answer that did not change at all,
  or the one cost the countermeasure does add and discloses: signing now reads
  the entropy source even where the caller fixed every other value the
  signature depends on.
* Six classes, and only six, take as their subject a step the countermeasure
  ADDED rather than a property of a step that was already there:
  `TestFixedDigitRecoding` for the recoding, `TestCanonicalScalar` for the
  canonical multiplier, `TestSignedDigitSymmetry` for the negation a signed
  digit costs, `TestNarrowOrderHardening` for the floor the recoding puts on the
  order, `TestBlindedInversion` for the blinding factor, and
  `TestMultiplierNormalisation` for the normalising step every multiplication
  now starts with.  That is the criterion, stated so a reader can apply it: a
  class is of the added kind when the step it names did not exist before the
  countermeasure, and an oracle when the step it names did exist and either did
  not change or changed only in what it costs.  The other eight classes here
  all name something the unmodified tree did too -- the additions of a
  multiplication, the doublings of an exchange, what the old padding did to a
  nonce, what the old reduction left of a hash, the products of the edge case
  multipliers, the bytes of a signature -- or, in the case of
  `TestOperationCounter`, the instrumentation rather than the library.  Two
  individual tests of `TestEdgeCasePreservation`, named below, are of the
  added kind inside a class that is otherwise an oracle.
* `TestPointDoublingCountInvariance` fails in eleven of its twelve tests.  The
  leak the class exists for is in its table less part, the ladder an ECDH
  exchange drives, where the number of doublings followed the bit length of
  the multiplier.  That a multiplication against a filled table performs no
  doubling at all did hold before the countermeasure as well -- but the three
  tests which assert it fail there too, because each of them pins the number
  of additions of the same multiplication alongside the doublings, and the
  count it is compared against is one the unmodified tree does not define.
  The one test that passes there asks only that the two ladders agree on the
  product.
* `TestECDHKeyAgreement` fails in seven of its ten tests, and it is the class
  that states the honest limit of this change as well as the gain.  The gain:
  an exchange whose remote public point carries the curve order -- a
  `ecdsa.keys.VerifyingKey` this process derived from a
  `ecdsa.keys.SigningKey` -- costs one fixed number of point operations on this
  tree, where on the unmodified one the same exchange performs 256, 192, 128
  and 64 point doublings for a NIST256p private key of those bit lengths, the
  cost following the long term key exactly.  Those seven failures are that
  count and the shapes it is derived from.  The limit: a public point that
  arrived from an encoding carries no order, nothing attaches one to it, and an
  exchange against it keeps the multiplier driven ladder on both trees, so its
  doubling count still follows the private key.  Three tests pass either way,
  and they are what makes the limit a measured statement rather than an
  omission -- the agreement of the two peers, that a decoded key reports no
  order, and that an exchange against one is driven by the private key on both
  trees alike.
* `TestSignatureTransparency` passes before and after, every one of its eleven
  tests.  It is the oracle for the countermeasure being invisible from the
  outside: the signatures it asserts are the bytes the unmodified tree
  produced.
* `TestEdgeCasePreservation` passes in twelve of its sixteen tests there, and
  those twelve are what the class is for: the products of zero, one, the
  order, its multiples and one less than it, on every shape of point, are the
  products the unmodified tree gave -- down to which of those multipliers hand
  back the very object that was multiplied.  Of the four that fail, one asks
  what those multipliers cost, which is the one thing about them the
  countermeasure did change; one asserts the products of a point at infinity
  that carries an order, which are the same on both trees, but asks the module
  first whether that order is one the recoding can use, which the unmodified
  tree cannot answer; and the last two are the two edges that a `None` reaches,
  refused here and read as a zero there, which is the caller visible change
  `TestMultiplierNormalisation` is about.
* `TestOperationCounter` guards the instrumentation the counting tests are
  built on rather than the library.  Only the one of its six tests that states
  an operation count needs the countermeasure to be there; the rest pass
  either way.

Counted against that tree, 111 of the 160 tests in this file failed and 49
passed, class by class: 12 of 12 in `TestPointAdditionCountInvariance`, 11 of
12 in `TestPointDoublingCountInvariance`, 7 of 10 in `TestECDHKeyAgreement`,
12 of 13 in `TestFixedDigitRecoding`, 21 of 22 in `TestCanonicalScalar`, 12 of
15 in `TestNarrowOrderHardening`, 5 of 6 in `TestSignedDigitSymmetry`, 6 of 10
in `TestNonceUnpaddingRegression`, 2 of 4 in `TestEdwardsRawScalarRegression`,
9 of 12 in `TestMultiplierNormalisation`, 9 of 11 in `TestBlindedInversion`,
1 of 6 in `TestOperationCounter` and 4 of 16 in `TestEdgeCasePreservation`
failed, while 0 of 11 in `TestSignatureTransparency` did.
"""

import os
import pickle
import sys

try:
    import unittest2 as unittest
except ImportError:
    import unittest

import hashlib
import hypothesis.strategies as st
from hypothesis import given, settings

from . import ecdsa as ecdsa_module
from . import ellipticcurve
from . import numbertheory as numbertheory_module
from ._compat import a2b_hex, bit_length
from .curves import (
    curves,
    BRAINPOOLP256r1,
    BRAINPOOLP384r1,
    BRAINPOOLP512r1,
    Ed448,
    Ed25519,
    NIST256p,
    SECP112r2,
    SECP160r1,
    SECP256k1,
)
from .ecdh import ECDH
from .ecdsa import Private_key, Public_key, RSZeroError
from .eddsa import PrivateKey as EdDSAPrivateKey
from .ellipticcurve import (
    CurveEdTw,
    CurveFp,
    INFINITY,
    Point,
    PointEdwards,
    PointJacobi,
)
from .keys import SigningKey, VerifyingKey
from .numbertheory import gcd, inverse_mod
from .util import (
    randrange,
    sigdecode_der,
    sigdecode_string,
    sigencode_der,
)


NO_OLD_SETTINGS = {}
if sys.version_info > (2, 7):  # pragma: no branch
    NO_OLD_SETTINGS["deadline"] = 5000


SLOW_SETTINGS = {}
if "--fast" in sys.argv:  # pragma: no cover
    SLOW_SETTINGS["max_examples"] = 2
else:
    SLOW_SETTINGS["max_examples"] = 10


# a bounded number of Hypothesis examples and a deadline wide enough for a
# scalar multiplication, for the properties that need real point arithmetic
POINT_SETTINGS = dict(NO_OLD_SETTINGS)
POINT_SETTINGS.update(SLOW_SETTINGS)


# How many multipliers of each bit width the operation count tests use.  More
# than one is what makes a count per width a constant that was established
# rather than one that was hit by accident; the cap is taken from the example
# budget above so that `--fast` shortens these tests as well without adding a
# second branch on the command line to the one already excluded from coverage.
SCALARS_PER_WIDTH = min(SLOW_SETTINGS["max_examples"], 8)


# The three families of 256 bit short Weierstrass curve `ecdsa.curves`
# registers, used wherever an assertion has to hold across curves of one size
# rather than across sizes.  A narrower curve (SECP160r1), a wider one
# (BRAINPOOLP384r1) and an Edwards curve (Ed25519) are named by the individual
# tests that need them, since the four ladders the countermeasure covers are
# reached per curve type and per whether the point carries a multiplication
# table.
CURVES_256_BIT = (NIST256p, SECP256k1, BRAINPOOLP256r1)


# A linear congruential generator, used instead of `random` so that the
# multipliers these tests use are the same on every interpreter and every
# release -- `random.Random.randrange()` is not.  The constants are the ones
# Knuth lists for a 64 bit state; nothing here is a source of randomness for
# any cryptographic purpose, and no test depends on the values themselves,
# only on their bit widths.
_LCG_MULTIPLIER = 6364136223846793005
_LCG_INCREMENT = 1442695040888963407
_LCG_MASK = (1 << 64) - 1

#: The narrowest order the fixed length recoding can be used for.  Every digit
#: the recoding emits is odd and below ``2 ** window`` in absolute value, and a
#: ladder answers a digit with the odd multiple of the point that it names, so
#: an order no larger than the largest of those digits is one where such an odd
#: multiple is a multiple of the order -- the point at infinity, which the
#: affine entries of a multiplication table cannot hold.  At the one digit
#: width the module uses the largest digit is fifteen, and the narrowest odd
#: order above it is seventeen.  Spelled as a literal so that the tests below
#: state the boundary rather than recompute the rule that produced it;
#: `TestNarrowOrderHardening` checks the two against each other.
SMALLEST_ORDER = 17


def scalars_of_width(width, count, seed=1):
    """
    Return `count` distinct-looking integers of exactly `width` bits.

    The top bit of every returned value is set, so `bit_length()` of each one
    is exactly `width`; the bits below it come from the generator above, which
    makes the sequence reproducible across interpreters.

    :param int width: bit length every returned integer has, at least two
    :param int count: how many integers to return
    :param int seed: distinguishes the sequences of two callers

    :return: the integers, in generation order
    :rtype: list of int
    """
    assert width > 1
    state = (seed * 2654435761 + width) & _LCG_MASK
    top = 1 << (width - 1)
    mask = top - 1
    scalars = []
    while len(scalars) < count:
        value = 0
        produced = 0
        while produced < width:
            state = (state * _LCG_MULTIPLIER + _LCG_INCREMENT) & _LCG_MASK
            # the low half of an LCG state is the poor half, so only the top
            # 32 bits of each step are used
            value = (value << 32) | (state >> 32)
            produced += 32
        scalars.append(top | (value & mask))
    return scalars


def stratified_widths(order):
    """
    Bit widths of the multipliers an operation count test walks.

    The widest is the width of the order itself and the narrowest is 96 bits
    below it, which on the smallest curve here leaves 65 bits: far enough down
    that the number of point operations of the code this countermeasure
    replaced differed by tens of additions between the two ends.

    :param order: order of the point that will be multiplied

    :return: the bit widths, widest first
    :rtype: list of int
    """
    widths = []
    top = bit_length(int(order))
    for below in (0, 6, 16, 32, 64, 96):
        if top - below > 8:
            widths.append(top - below)
    return widths


def fixed_ladder_shape(order, window=None):
    """
    Shape of the fixed length ladder of a point of `order`.

    Returns the number of digits a multiplier is recoded into and the number of
    entries the multiplication table of a generator therefore holds -- the odd
    multiples a whole window can select, for every position including the most
    significant one, so that the work of reading a position does not say which
    position was read.

    Both are derived here from the order and the window alone: a canonical
    multiplier is below three times the order and so below
    ``2 ** (bit_length(order) + 2)``, and the digit positions split those bits
    into as few whole windows as possible.  Asking
    `PointJacobi._fixed_digit_count()` and
    `_fixed_table_length()` instead would make every expectation below agree
    with the implementation by construction, and so let a wrong count through;
    the one thing read from the module is the window width, which is a tuning
    choice rather than a property of the countermeasure.

    :param order: order of the point
    :param window: the digit width to use, the one the module is built with by
        default.  Passing it explicitly is how the tests state a count as a
        literal without that literal depending on the module's own choice.

    :return: the number of digits and the number of table entries
    :rtype: tuple of two int
    """
    order = int(order)
    if window is None:
        window = ellipticcurve._MUL_WINDOW
    width = bit_length(order) + 2
    digits = width // window + (1 if width % window else 0)
    entries = digits * (1 << (window - 1))
    return digits, entries


def table_less_shape(curve, window=None):
    """
    Additions and doublings a multiplication without a table performs.

    One addition per digit plus the ones that build the odd multiples of the
    point, and a whole window of doublings per digit -- except that the
    Weierstrass ladder skips the window before the most significant digit,
    which has nothing but the point at infinity to act on, while the Edwards
    one performs it.  Both spend one further doubling on the step between
    consecutive odd multiples.

    This is the shape of every multiplication of a point that knows its order
    but carries no table, which is what an ECDH exchange multiplies.

    :param curve: the curve the point belongs to
    :param window: the digit width to use, the one the module is built with by
        default

    :return: the number of additions and the number of doublings
    :rtype: tuple of two int
    """
    if window is None:
        window = ellipticcurve._MUL_WINDOW
    digits, _ = fixed_ladder_shape(curve.order, window)
    additions = digits + (1 << (window - 1)) - 1
    if isinstance(curve.generator, PointEdwards):
        return additions, digits * window + 1
    return additions, (digits - 1) * window + 1


def count_point_operations(point_class, work):
    """
    Count the point additions and doublings a call performs.

    The two methods that every ladder of `point_class` dispatches its
    arithmetic through are replaced by counting wrappers for the duration of
    the call and restored in a `finally`, so that no other test and no other
    caller in the process ever sees a patched class.  The wrappers take their
    arguments as `*args` and hand them straight on, both because the two point
    classes give their formulas different parameter lists and so that they
    keep working if a formula is ever re-signatured.

    Only the two dispatchers are wrapped.  The formulas they choose between
    are left alone, so a change in which of them a ladder ends up using does
    not change what is counted here.

    :param point_class: `PointJacobi` or `PointEdwards`
    :param callable work: called once, with no arguments

    :return: what `work` returned, the number of additions and the number of
        doublings
    :rtype: tuple of object, int, int
    """
    original_add = point_class.__dict__["_add"]
    original_double = point_class.__dict__["_double"]
    counted = [0, 0]

    def counting_add(*args, **kwargs):
        counted[0] += 1
        return original_add(*args, **kwargs)

    def counting_double(*args, **kwargs):
        counted[1] += 1
        return original_double(*args, **kwargs)

    point_class._add = counting_add
    point_class._double = counting_double
    try:
        result = work()
    finally:
        point_class._add = original_add
        point_class._double = original_double
    return result, counted[0], counted[1]


def count_formula_calls(point_class, names, work):
    """
    Count the individual coordinate formulas a call reaches.

    `count_point_operations()` wraps only the two dispatchers, `_add()` and
    `_double()`, so a multiplier that steers a ladder from one addition formula
    into another -- or into a doubling formula, which is what an addition of two
    equal points is answered with -- changes nothing it can see.  This wraps
    every formula named, so that substitution is visible.

    Every wrapper is removed again in a `finally`, so that no other test and no
    other caller in the process ever sees a patched class.

    :param point_class: `PointJacobi` or `PointEdwards`
    :param names: the methods to count, as they are spelled on the class
    :param callable work: called once, with no arguments

    :return: what `work` returned, and the call count of every named method as
        a tuple of name and count pairs in the order they were given
    :rtype: tuple of object and tuple
    """
    originals = {}
    counted = {}

    def wrap(name):
        original = point_class.__dict__[name]
        originals[name] = original
        counted[name] = 0

        def counting(*args, **kwargs):
            counted[name] += 1
            return original(*args, **kwargs)

        setattr(point_class, name, counting)

    try:
        for name in names:
            wrap(name)
        result = work()
    finally:
        for name, original in originals.items():
            setattr(point_class, name, original)
    return result, tuple((name, counted[name]) for name in names)


#: the formulas `PointJacobi._add()` and `_double()` dispatch to, plus the two
#: dispatchers themselves.  An addition of two equal points is answered by
#: `_double_with_z_1()`, which no count of the dispatchers alone can see.
JACOBI_FORMULAS = (
    "_add",
    "_add_with_z_1",
    "_add_with_z_eq",
    "_add_with_z2_1",
    "_add_with_z_ne",
    "_double",
    "_double_with_z_1",
)

#: the twisted Edwards implementation keeps one addition formula and one
#: doubling formula, and its addition dispatches back through `_double()` for
#: two equal points, so the two dispatchers are the whole set here
EDWARDS_FORMULAS = ("_add", "_double")


def formulas_of(curve):
    """Return the formula names to count for the point class of `curve`."""
    if point_class_of(curve) is PointEdwards:
        return EDWARDS_FORMULAS
    return JACOBI_FORMULAS


def captured_multipliers(point_class, work):
    """
    Return the multipliers a call handed to the multiplication of a point.

    The multiplication of `point_class` is replaced by a recording wrapper for
    the duration of the call and restored in a `finally`, exactly as
    `count_point_operations()` treats the two formula dispatchers, so that no
    later test sees a patched class.  A multiplier reaches a point through
    `__rmul__` as often as through `__mul__` -- `k * G` is the form the signing
    path uses -- and `__rmul__` multiplies through `__mul__`, so wrapping the
    one records both.

    :param point_class: `PointJacobi` or `PointEdwards`
    :param callable work: called once, with no arguments

    :return: what `work` returned and the multipliers it handed over, in the
        order they were handed over
    :rtype: tuple of object, list
    """
    original_mul = point_class.__dict__["__mul__"]
    captured = []

    def capturing_mul(self, other):
        captured.append(other)
        return original_mul(self, other)

    point_class.__mul__ = capturing_mul
    try:
        result = work()
    finally:
        point_class.__mul__ = original_mul
    return result, captured


def multiplier(point, scalar):
    def multiply():
        return point * scalar

    return multiply


# The integer type wide field coordinates are held in.  Python 2 keeps values
# past its machine word in `long`, so subclassing `int` there would truncate a
# curve coordinate; Python 3 has the one type.
try:
    _INT_BASE = long
except NameError:
    _INT_BASE = int


class NegationCounter(_INT_BASE):
    """
    An integer that records every time it is negated.

    Instances stand in for the coordinates a multiplication table holds, which
    turns the negation a signed digit asks for into something a test can count.
    Subclassing the integer type leaves every arithmetic operation the addition
    formulas perform working exactly as it did, because arithmetic on a
    subclass of an integer answers with the plain type -- so nothing the
    formulas compute from one of these is counted, only the negation of the
    table entry itself.

    The counter is a class attribute rather than an instance one because the
    instances are consumed by arithmetic that answers with plain integers.
    """

    counted = [0]

    def __neg__(self):
        NegationCounter.counted[0] += 1
        return _INT_BASE.__neg__(self)


def _wrap_coordinates(entries):
    """Return `entries` with every coordinate counted, shape preserved."""
    return [
        tuple(NegationCounter(value) for value in entry) for entry in entries
    ]


def count_coordinate_negations(point, scalar):
    """
    Count the field wide negations a multiplication performs.

    A signed digit selects a table entry and then asks for the negation of one
    of its coordinates -- two of them on the twisted Edwards points, where the
    product of the affine coordinates is negated along with the x one.  Doing
    that work only for the digits that are negative would leave the number of
    negative digits, which follows the multiplier, in the run time, so both
    polarities are derived for every digit and the answer is picked out by
    index.  This counts the negations so that the claim is asserted rather than
    assumed.

    The instrument differs between the two fixed work paths because the table
    lives in a different place in each.  A generator holds it as an attribute,
    which can simply be replaced with a counted copy.  A point without one
    builds it inside the multiplication, so the call that produces the entries
    is wrapped instead: `_scaled_all()` for the Weierstrass points, and
    `_add()` together with the coordinates of the point itself for the twisted
    Edwards ones, whose table needs no rescaling.  Everything is restored in a
    `finally`, so no other test sees a patched class or a patched point.

    :param point: the point to multiply, which must know its order
    :param int scalar: the multiplier

    :return: the product and the number of negations
    :rtype: tuple of object, int
    """
    point_class = type(point)
    attribute = "_%s__precompute" % point_class.__name__
    table = precompute_table(point)
    NegationCounter.counted[0] = 0

    if table:
        setattr(point, attribute, _wrap_coordinates(table))
        try:
            product = point * scalar
        finally:
            setattr(point, attribute, table)
    elif point_class is PointEdwards:
        coordinates = "_PointEdwards__coords"
        original_add = point_class.__dict__["_add"]
        original_coordinates = getattr(point, coordinates)

        def counted_add(*args, **kwargs):
            return tuple(
                NegationCounter(value)
                for value in original_add(*args, **kwargs)
            )

        setattr(
            point,
            coordinates,
            tuple(NegationCounter(v) for v in original_coordinates),
        )
        point_class._add = counted_add
        try:
            NegationCounter.counted[0] = 0
            product = point * scalar
        finally:
            point_class._add = original_add
            setattr(point, coordinates, original_coordinates)
    else:
        original_scaled_all = point_class.__dict__["_scaled_all"]

        def counted_scaled_all(points, prime):
            return _wrap_coordinates(original_scaled_all(points, prime))

        point_class._scaled_all = staticmethod(counted_scaled_all)
        try:
            NegationCounter.counted[0] = 0
            product = point * scalar
        finally:
            point_class._scaled_all = original_scaled_all
    return product, NegationCounter.counted[0]


def point_class_of(curve):
    return type(curve.generator)


def rebuilt_generator(curve, generator=True):
    """
    Return a generator-like copy of the generator of `curve`.

    The generators `ecdsa.curves` holds are shared for the life of the
    process, so by the time this module runs another test may well have filled
    their multiplication tables already.  A test that needs an unfilled one
    therefore has to build its own point rather than assume anything about
    theirs, and a test that needs a filled one has to fill it itself.

    :param curve: the curve whose generator to copy
    :param bool generator: whether the copy is marked as a curve generator,
        and so whether it builds a multiplication table at all

    :return: the copy, with an empty multiplication table
    """
    point = curve.generator
    order = point.order()
    if isinstance(point, PointEdwards):
        return PointEdwards(
            point.curve(),
            point.x(),
            point.y(),
            1,
            point.x() * point.y(),
            order,
            generator,
        )
    return PointJacobi(
        point.curve(), point.x(), point.y(), 1, order, generator
    )


def order_less_point(curve):
    """Return a copy of the generator of `curve` that knows no order."""
    point = curve.generator
    if isinstance(point, PointEdwards):
        return PointEdwards(
            point.curve(), point.x(), point.y(), 1, point.x() * point.y()
        )
    return PointJacobi(point.curve(), point.x(), point.y(), 1)


def precompute_table(point):
    """
    Return the multiplication table of `point`.

    The attribute is private to its class, so it is reached through the name
    the class mangled it to, exactly as `test_jacobi` reaches it.
    """
    if isinstance(point, PointEdwards):
        return point._PointEdwards__precompute
    return point._PointJacobi__precompute


def warm_generator(curve):
    """
    Return the generator of `curve` with its multiplication table filled.

    Filling it is what the first multiplication by any multiplier does, so
    doing it here rather than inside a measurement keeps the one-off cost of
    building the table out of the numbers a test compares.
    """
    point = curve.generator
    point * 2
    return point


# Stand-ins for a multiplier that offers `__index__()`, the protocol by which
# Python asks a value for its lossless integer.  The first two answer with an
# integer and are accepted: `int`, `bool` and the ``mpz`` of both gmpy releases
# are the types this library actually meets, and these stand in for the two of
# those that may not be installed, one of them answering with a value far wider
# than any curve order.  The four after them answer with something that is not
# an integer and are refused, as surely as a multiplier that offers no
# `__index__()` at all: the normalising step reduces its answer modulo the
# order of the point, and reducing the string "3" yields three, so accepting it
# would multiply the point by a number its caller never asked for.  Each is
# named for the type it answers with, because the refusal names the type of the
# multiplier itself and the tests assert that message exactly.
class Multiplier(object):
    def __index__(self):
        return 11


class WideMultiplier(object):
    def __index__(self):
        return 1 << 300


class StringMultiplier(object):
    def __index__(self):
        return "3"


class FloatMultiplier(object):
    def __index__(self):
        return 3.0


class NoneMultiplier(object):
    def __index__(self):
        return None


class ListMultiplier(object):
    def __index__(self):
        return [3]


class RecordingNumbertheory(object):
    """
    Stands in for the `numbertheory` module, recording what it is asked to
    invert.

    Every other name is forwarded to the real module, so a caller that reaches
    for `gcd()` or anything else is unaffected.  Only the module reference a
    single other module holds is replaced by one of these, never the function
    inside the real module, because that function object is shared with
    `ellipticcurve`, which inverts a field element on every point scaling.
    """

    def __init__(self, wrapped, operands):
        self._wrapped = wrapped
        self._operands = operands

    def inverse_mod(self, value, modulus):
        self._operands.append((value, modulus))
        return self._wrapped.inverse_mod(value, modulus)

    def __getattr__(self, name):
        return getattr(self._wrapped, name)


def canonical_scalar(scalar, order):
    return PointJacobi._canonical_scalar(scalar, order)


def equal_operand_residues(order, window=None):
    """
    The residues whose ladder ends on two equal operands.

    A ladder adds the digit of the lowest position last, to an accumulator that
    by then holds the canonical multiplier minus that digit times the point, so
    the two operands of that addition coincide exactly where the canonical
    value is congruent to twice that digit modulo the order.  The digit is odd
    and below ``2 ** window`` in absolute value, so there is one candidate
    residue per digit to check and no search is needed.

    At most two residues of any order qualify, and none at all for some.  Where
    one does, a short Weierstrass ladder answers that addition with
    `PointJacobi._double_with_z_1()` from inside the addition formula, which
    moves neither of the two counted dispatchers, while a twisted Edwards
    ladder dispatches back through `PointEdwards._double()` and so pays one
    counted doubling more.  Which addition formula answers it follows the digit
    count: `PointJacobi._add_with_z2_1()` for a recoding of three digits or
    more, and `PointJacobi._add_with_z_1()` where it is two -- reaching that
    second one is what the groups at the floor of `TestNarrowOrderHardening`
    exist for.  `TestCanonicalScalar` names the residues of the registered
    curves and measures both, and ``SECURITY.md`` records the residual.

    :param int order: order of the point
    :param window: the digit width, the one the module uses by default

    :return: the residues, ascending
    :rtype: list of int
    """
    order = int(order)
    if window is None:
        window = ellipticcurve._MUL_WINDOW
    low_bits = 1 << (window + 1)
    half = low_bits >> 1
    found = []
    for digit in range(1 - half, half, 2):
        residue = (2 * digit) % order
        canonical = canonical_scalar(residue, order)
        if (canonical % low_bits) - half == digit:
            found.append(residue)
    return sorted(set(found))


def old_padding_was_cancelled(scalar, order):
    """
    Would the padding releases up to 0.19.1 applied have been annihilated?

    Those releases added the order to the nonce, and the order once more if
    that had not widened it, and the multiplication then reduced the result
    modulo twice the order.  The first of the two survived that reduction and
    the second did not, so the countermeasure was cancelled exactly for the
    nonces that took the second branch.

    :param int scalar: the nonce, before any padding
    :param order: order of the generator

    :return: whether the padding was undone for this nonce
    :rtype: bool
    """
    order = int(order)
    scalar = int(scalar) % order
    return bit_length(scalar + order) == bit_length(order)


class TestOperationCounter(unittest.TestCase):
    """
    The instrumentation the other tests use must not leak out of them.

    A counting wrapper left installed on a point class would be seen by every
    later test in the process and by every other caller in it, so its removal
    is asserted here rather than assumed.
    """

    def test_the_methods_are_restored_afterwards(self):
        for point_class in (PointJacobi, PointEdwards):
            original_add = point_class.__dict__["_add"]
            original_double = point_class.__dict__["_double"]

            count_point_operations(point_class, lambda: None)

            self.assertIs(point_class.__dict__["_add"], original_add)
            self.assertIs(point_class.__dict__["_double"], original_double)

    def test_the_methods_are_restored_after_an_exception(self):
        def explode():
            raise ValueError("measured work failed")

        for point_class in (PointJacobi, PointEdwards):
            original_add = point_class.__dict__["_add"]
            original_double = point_class.__dict__["_double"]

            self.assertRaises(
                ValueError, count_point_operations, point_class, explode
            )

            self.assertIs(point_class.__dict__["_add"], original_add)
            self.assertIs(point_class.__dict__["_double"], original_double)

    def test_the_multiplication_is_restored_afterwards(self):
        def explode():
            raise ValueError("measured work failed")

        for point_class in (PointJacobi, PointEdwards):
            original_mul = point_class.__dict__["__mul__"]

            captured_multipliers(point_class, lambda: None)
            self.assertIs(point_class.__dict__["__mul__"], original_mul)

            self.assertRaises(
                ValueError, captured_multipliers, point_class, explode
            )
            self.assertIs(point_class.__dict__["__mul__"], original_mul)

    def test_the_multipliers_handed_over_are_the_ones_captured(self):
        generator = warm_generator(SECP160r1)

        def multiply_twice():
            return (generator * 5, 7 * generator)

        products, multipliers = captured_multipliers(
            PointJacobi, multiply_twice
        )

        # both spellings are recorded, in the order they were used, and the
        # products are the ones the unwrapped multiplication gives
        self.assertEqual(multipliers, [5, 7])
        self.assertEqual(products, (generator * 5, generator * 7))

    def test_the_counters_count_the_operations(self):
        generator = warm_generator(SECP160r1)
        digits, _ = fixed_ladder_shape(SECP160r1.order)

        product, additions, doublings = count_point_operations(
            PointJacobi, multiplier(generator, 12345)
        )

        # the result is handed back untouched, and the counts are the ones the
        # multiplication really performed rather than a wrapped-away zero
        self.assertEqual(product, generator * 12345)
        self.assertEqual(additions, digits)
        self.assertEqual(doublings, 0)

    def test_no_operation_is_counted_for_work_that_does_none(self):
        _, additions, doublings = count_point_operations(
            PointJacobi, lambda: 1 + 1
        )

        self.assertEqual(additions, 0)
        self.assertEqual(doublings, 0)


class TestPointAdditionCountInvariance(unittest.TestCase):
    """
    The number of point additions must not follow the multiplier (Defect #2).

    A multiplication by a point that carries a multiplication table -- the
    signing and the key generation case -- performs exactly one addition per
    digit of the recoding of the multiplier and no doubling at all, and the
    number of digits is derived from the order of the point.  Before the
    countermeasure an addition was performed only for the non-zero digits of a
    non adjacent form, so the count was the Hamming weight of that form: a
    quantity that both varies between multipliers of one width and falls as the
    width falls, which is what let the width of the nonce be read off it.

    The claim covers every multiplier such a point accepts, with no exception
    carved out for the narrow ones: zero and one cost what a full width nonce
    costs, which is what the last test of this class asserts.
    `TestECDHKeyAgreement` asserts the invariance of the other ladder, the one
    without a table, through the entry point that multiplies by a long term
    private key.
    """

    def assert_addition_count_is_fixed(self, curve, widths, seed=1):
        generator = warm_generator(curve)
        point_class = point_class_of(curve)
        digits, _ = fixed_ladder_shape(curve.order)

        additions = set()
        doublings = set()
        for width in widths:
            for scalar in scalars_of_width(width, SCALARS_PER_WIDTH, seed):
                _, added, doubled = count_point_operations(
                    point_class, multiplier(generator, scalar)
                )
                additions.add(added)
                doublings.add(doubled)

        # one count for every multiplier of every width, and that one count is
        # the number the order of the curve asks for.  Both halves are needed:
        # the first is the property the countermeasure exists for, the second
        # rules out a count that is uniform but wrong
        self.assertEqual(len(additions), 1)
        self.assertEqual(sorted(additions), [digits])
        self.assertEqual(sorted(doublings), [0])

    def test_the_addition_count_the_curves_ask_for(self):
        """
        The count every parameterised curve asks for, from literal numbers.

        The bit length of each order and the addition count that follows from
        it are carried here as literals, so that the arithmetic the
        implementation performs is checked against numbers this test brings
        with it rather than against another expression of the same formula.
        Two forms are asserted.  The first re-derives the count from the
        literal bit length at whatever window the module is built with -- two
        bits wider than the order, rounded up to a whole number of windows.
        Two bits and not three: a canonical scalar is below three times the
        order, which is below two bits above it, and the two figures happen to
        round to the same number of four bit windows on every curve below, so a
        window of three is what tells them apart -- P-256 needs 86 windows of
        three from 258 bits and would need 87 from 259.
        The second and third pass a window explicitly, four and then three,
        which is what makes the familiar 65 additions of P-256 a literal in
        this file and what pins the two extra bits down: a window of four
        cannot tell two bits from three, and a window of three can.
        """
        expected = (
            (NIST256p, 256, 65, 86),
            (SECP256k1, 256, 65, 86),
            (BRAINPOOLP256r1, 256, 65, 86),
            (BRAINPOOLP384r1, 384, 97, 129),
            (BRAINPOOLP512r1, 512, 129, 172),
            (SECP160r1, 161, 41, 55),
            (Ed25519, 253, 64, 85),
        )
        for curve, order_bits, at_window_four, at_window_three in expected:
            self.assertEqual(bit_length(int(curve.order)), order_bits)
            digits, _ = fixed_ladder_shape(curve.order)
            # -(-a // b) is the ceiling of a / b without going through a float,
            # which at these magnitudes would not be exact
            self.assertEqual(
                digits, -(-(order_bits + 2) // ellipticcurve._MUL_WINDOW)
            )
            self.assertEqual(
                PointJacobi._fixed_digit_count(curve.order, 4),
                at_window_four,
            )
            self.assertEqual(
                PointJacobi._fixed_digit_count(curve.order, 3),
                at_window_three,
            )

    def test_addition_count_on_nist256p(self):
        self.assert_addition_count_is_fixed(
            NIST256p, stratified_widths(NIST256p.order)
        )

    def test_addition_count_on_nist256p_at_the_reported_widths(self):
        """
        The bit widths the advisory itself groups the nonces of P-256 into.

        Held to the absolute widths rather than to widths relative to the
        order, so that the curve the attack was reported against is covered
        exactly as it was reported, all the way down to a nonce a quarter of
        the width of the order.
        """
        self.assert_addition_count_is_fixed(
            NIST256p, (256, 250, 240, 224, 192, 128, 64), seed=2
        )

    def test_addition_count_on_secp256k1(self):
        self.assert_addition_count_is_fixed(
            SECP256k1, stratified_widths(SECP256k1.order)
        )

    def test_addition_count_on_brainpoolp256r1(self):
        self.assert_addition_count_is_fixed(
            BRAINPOOLP256r1, stratified_widths(BRAINPOOLP256r1.order)
        )

    def test_addition_count_on_secp160r1(self):
        self.assert_addition_count_is_fixed(
            SECP160r1, stratified_widths(SECP160r1.order)
        )

    def test_addition_count_on_ed25519(self):
        """The Edwards ladder, which EdDSA signing drives with a hash."""
        self.assert_addition_count_is_fixed(
            Ed25519, stratified_widths(Ed25519.order)
        )

    def test_addition_count_on_brainpoolp384r1(self):
        self.assert_addition_count_is_fixed(
            BRAINPOOLP384r1, stratified_widths(BRAINPOOLP384r1.order)
        )

    def test_addition_count_on_brainpoolp512r1(self):
        self.assert_addition_count_is_fixed(
            BRAINPOOLP512r1, stratified_widths(BRAINPOOLP512r1.order)
        )

    def test_the_widest_and_the_narrowest_multiplier_agree(self):
        """
        The two ends of the range, stated on their own.

        This is the comparison a timing attack makes: it keeps the signatures
        that were produced with a short nonce and compares them against the
        rest.  Asserting the two ends against each other, rather than only the
        size of a set of counts, says plainly which two numbers had to differ
        for the attack to work.
        """
        for curve in (NIST256p, SECP160r1, Ed25519):
            generator = warm_generator(curve)
            point_class = point_class_of(curve)
            digits, _ = fixed_ladder_shape(curve.order)
            top = bit_length(int(curve.order))

            _, widest, _ = count_point_operations(
                point_class,
                multiplier(generator, scalars_of_width(top, 1)[0]),
            )
            _, narrowest, _ = count_point_operations(
                point_class,
                multiplier(generator, scalars_of_width(64, 1)[0]),
            )

            self.assertEqual(widest, narrowest)
            self.assertEqual(widest, digits)

    def test_no_multiplier_is_answered_without_the_fixed_work(self):
        """
        Zero and one cost what a full width multiplier costs.

        A multiplication used to answer these two before it derived anything
        from the multiplier, so both spent no point operation at all, while an
        ordinary multiplier of the same point spent an addition for every
        non-zero digit of its non adjacent form -- a count in the tens on a 256
        bit curve, where all of them now spend the 65 additions the recoding
        asks for.  One of the two is a value a secret takes: `sign_digest()`
        signs with a nonce of one and the signature verifies, and key
        generation and an ECDH exchange accept one as the private key, so it
        was exactly a multiplier a ladder is there to hide, told apart from
        every other by the work a multiplication did not do.  Zero is refused
        by those entry points and is asserted here because it is the other
        multiplier the old short circuit answered, and because leaving it out
        would leave the ladder free to grow a short circuit again.  Both are
        still answered with the point at infinity and with the point that was
        multiplied, which `TestEdgeCasePreservation` pins; what this test adds
        is that they reach those answers through the ladder.
        """
        for curve in (NIST256p, SECP160r1, Ed25519):
            order = int(curve.order)
            generator = warm_generator(curve)
            point_class = point_class_of(curve)
            digits, _ = fixed_ladder_shape(curve.order)
            scalars = [0, 1, 2, 3, order - 1, order, order + 1, 2 * order]
            scalars.extend(scalars_of_width(bit_length(order), 2, seed=41))
            scalars.extend(scalars_of_width(64, 2, seed=42))

            counts = set()
            for scalar in scalars:
                _, added, doubled = count_point_operations(
                    point_class, multiplier(generator, scalar)
                )
                counts.add((added, doubled))

            self.assertEqual(sorted(counts), [(digits, 0)])

    def test_a_point_restored_from_a_pickle_costs_the_fixed_count(self):
        """
        Serialising a point does not hand the count back to the multiplier.

        A point is picklable and the state it writes is its plain instance
        dictionary, multiplication table and all, exactly as every release up
        to 0.19.1 wrote it.  Two directions matter to the count.  A state
        written by this release carries a table of the layout the recoding
        indexes, that table is recognised on the way in, and the multiplication
        that follows costs the one addition per digit and the no doubling that
        a point which was never serialised costs -- so a caller that keeps its
        signing key pickled between processes is held to the same fixed cost as
        one that does not.  A state that carries a table of any other layout --
        what a release older than this countermeasure wrote, having filled the
        table with the successive doublings of the point -- is discarded on the
        way in and rebuilt, and the rebuild costs one addition per table entry
        and the doublings of a first multiplication, which is what a point that
        was never serialised at all costs; the count still follows the order of
        the point rather than the multiplier.  Neither direction may answer
        with a wrong point, which is asserted here as well because a table
        indexed under a layout it was not written in would do exactly that.
        """
        window = ellipticcurve._MUL_WINDOW
        for curve in (NIST256p, SECP160r1, Ed25519):
            point_class = point_class_of(curve)
            digits, entries = fixed_ladder_shape(curve.order)
            scalar = scalars_of_width(bit_length(int(curve.order)), 1)[0]
            expected = curve.generator * scalar

            warm = rebuilt_generator(curve)
            warm * 2
            self.assertEqual(len(precompute_table(warm)), entries)

            restored = pickle.loads(pickle.dumps(warm))

            self.assertEqual(len(precompute_table(restored)), entries)
            answer, added, doubled = count_point_operations(
                point_class, multiplier(restored, scalar)
            )
            self.assertEqual((added, doubled), (digits, 0))
            self.assertEqual(answer, expected)

            other_layout = rebuilt_generator(curve)
            other_layout * 2
            table = precompute_table(other_layout)
            del table[len(table) // 2 :]
            rebuilt = pickle.loads(pickle.dumps(other_layout))

            self.assertEqual(precompute_table(rebuilt), [])
            answer, added, doubled = count_point_operations(
                point_class, multiplier(rebuilt, scalar)
            )
            self.assertEqual(
                (added, doubled), (entries, window * (digits - 1) + 1)
            )
            self.assertEqual(answer, expected)


class TestPointDoublingCountInvariance(unittest.TestCase):
    """
    The number of point doublings must not follow the multiplier (Defect #3).

    Two separate claims, because the two ladders reach the number differently.
    A point that carries a multiplication table spends every doubling it will
    ever spend on building that table, during the first multiplication, and
    performs none at all afterwards; that was true before the countermeasure as
    well, and the wall clock probe at the root of this repository relies on it
    when it warms a generator before timing anything.  A point that knows its
    order but carries no table -- which is what an ECDH exchange multiplies,
    by the long term private key rather than by a single use nonce -- doubles a
    fixed number of times derived from that order.  Before the countermeasure
    that ladder ran once per digit of the non adjacent form of the multiplier,
    so its doubling count was determined by the bit length of the multiplier --
    a non adjacent form can carry one digit further than that length -- and the
    leak there exposed a key that does not change between signatures.
    """

    def expected_first_multiplication(self, curve, window=None):
        """
        Additions and doublings the multiplication that fills a table performs.

        The table holds the odd multiples of the point for every digit
        position, so building it costs one doubling for the step between
        consecutive odd multiples of a position and a whole window more to
        carry that step to the next position, and one addition for every entry
        but the first of each position.  Adding the additions the
        multiplication itself then performs, one per digit, brings the total to
        exactly one addition per table entry.
        """
        if window is None:
            window = ellipticcurve._MUL_WINDOW
        digits, entries = fixed_ladder_shape(curve.order, window)
        return entries, window * (digits - 1) + 1

    def expected_table_less_multiplication(self, curve, window=None):
        """
        Additions and doublings a multiplication without a table performs.

        Read from `table_less_shape()`.  The other place this shape is
        asserted, `TestECDHKeyAgreement`, writes the same two counts out again
        rather than calling that helper, so that the shape an exchange is held
        to does not come from the one expression this class checks.
        """
        return table_less_shape(curve, window)

    def assert_first_multiplication(self, curve, arity):
        generator = rebuilt_generator(curve)
        point_class = point_class_of(curve)
        digits, entries = fixed_ladder_shape(curve.order)
        scalar = scalars_of_width(bit_length(int(curve.order)), 1)[0]

        # a rebuilt generator has nothing cached, whatever the shared one that
        # `ecdsa.curves` holds may have had done to it by an earlier test
        self.assertEqual(precompute_table(generator), [])

        _, additions, doublings = count_point_operations(
            point_class, multiplier(generator, scalar)
        )

        expected = self.expected_first_multiplication(curve)
        self.assertEqual((additions, doublings), expected)
        # one addition per table entry, and the entries hold as many
        # coordinates as the addition formula of this curve type consumes
        self.assertEqual(additions, entries)
        self.assertGreater(entries, digits)
        self.assertEqual(len(precompute_table(generator)), entries)
        self.assertEqual(len(precompute_table(generator)[0]), arity)

    def test_first_multiplication_on_nist256p(self):
        self.assert_first_multiplication(NIST256p, 2)
        # the numbers the paragraphs above work out to, stated once as
        # literals so that a change to any of the formulas is caught here and
        # not only in a comparison of one derived value against another
        self.assertEqual(
            self.expected_first_multiplication(NIST256p, 4), (520, 257)
        )

    def test_first_multiplication_on_secp160r1(self):
        self.assert_first_multiplication(SECP160r1, 2)
        self.assertEqual(
            self.expected_first_multiplication(SECP160r1, 4), (328, 161)
        )

    def test_first_multiplication_on_ed25519(self):
        """Edwards table entries are triples, not pairs."""
        self.assert_first_multiplication(Ed25519, 3)
        self.assertEqual(
            self.expected_first_multiplication(Ed25519, 4), (512, 253)
        )

    def test_first_multiplication_on_brainpoolp384r1(self):
        self.assert_first_multiplication(BRAINPOOLP384r1, 2)
        self.assertEqual(
            self.expected_first_multiplication(BRAINPOOLP384r1, 4), (776, 385)
        )

    def assert_no_doubling_after_the_table_is_built(self, curve):
        generator = rebuilt_generator(curve)
        point_class = point_class_of(curve)
        digits, _ = fixed_ladder_shape(curve.order)
        top = bit_length(int(curve.order))

        count_point_operations(
            point_class, multiplier(generator, scalars_of_width(top, 1)[0])
        )

        # a second multiplier of the full width, and a third of a quarter of
        # it: neither costs a doubling, and both cost the same additions
        for width in (top, top // 4):
            scalar = scalars_of_width(width, 1, seed=3)[0]
            _, additions, doublings = count_point_operations(
                point_class, multiplier(generator, scalar)
            )
            self.assertEqual(doublings, 0)
            self.assertEqual(additions, digits)

    def test_no_doubling_after_the_table_is_built_on_nist256p(self):
        self.assert_no_doubling_after_the_table_is_built(NIST256p)

    def test_no_doubling_after_the_table_is_built_on_secp160r1(self):
        self.assert_no_doubling_after_the_table_is_built(SECP160r1)

    def test_no_doubling_after_the_table_is_built_on_ed25519(self):
        self.assert_no_doubling_after_the_table_is_built(Ed25519)

    def assert_table_less_count_is_fixed(self, curve):
        """
        Assert one operation count for the ladder without a table.

        This drives that ladder directly, with the order already attached, so
        it states a property of the ladder and nothing about how a point
        arrives at it.  `TestECDHKeyAgreement` covers that separately, through
        the public API and both settings of ``validate_point``.
        """
        point = rebuilt_generator(curve, generator=False)
        point_class = point_class_of(curve)

        # a point that is not marked as a curve generator builds no table, so
        # every multiplication of it takes the table-less ladder
        self.assertEqual(precompute_table(point), [])

        additions = set()
        doublings = set()
        for width in stratified_widths(curve.order):
            for scalar in scalars_of_width(width, SCALARS_PER_WIDTH, seed=4):
                _, added, doubled = count_point_operations(
                    point_class, multiplier(point, scalar)
                )
                additions.add(added)
                doublings.add(doubled)
        self.assertEqual(precompute_table(point), [])

        expected = self.expected_table_less_multiplication(curve)
        self.assertEqual(len(doublings), 1)
        self.assertEqual(
            (sorted(additions), sorted(doublings)),
            ([expected[0]], [expected[1]]),
        )

    def test_table_less_count_on_nist256p(self):
        self.assert_table_less_count_is_fixed(NIST256p)
        self.assertEqual(
            self.expected_table_less_multiplication(NIST256p, 4), (72, 257)
        )

    def test_table_less_count_on_secp160r1(self):
        self.assert_table_less_count_is_fixed(SECP160r1)
        self.assertEqual(
            self.expected_table_less_multiplication(SECP160r1, 4), (48, 161)
        )

    def test_table_less_count_on_ed25519(self):
        self.assert_table_less_count_is_fixed(Ed25519)
        self.assertEqual(
            self.expected_table_less_multiplication(Ed25519, 4), (71, 257)
        )

    def test_table_less_count_on_brainpoolp384r1(self):
        self.assert_table_less_count_is_fixed(BRAINPOOLP384r1)
        self.assertEqual(
            self.expected_table_less_multiplication(BRAINPOOLP384r1, 4),
            (104, 385),
        )

    def test_the_table_less_ladder_agrees_with_the_table_one(self):
        for curve in (SECP160r1, NIST256p, Ed25519):
            generator = warm_generator(curve)
            point = rebuilt_generator(curve, generator=False)
            for width in (bit_length(int(curve.order)), 64):
                for scalar in scalars_of_width(width, 2, seed=5):
                    self.assertEqual(point * scalar, generator * scalar)


class TestNarrowOrderHardening(unittest.TestCase):
    """
    Fixed work reaches every group the recoding can represent, not just curves.

    `ecdsa.ecdsa.Private_key` is public and takes any generator a caller hands
    it, so a nonce can be multiplied by a point of an order no registered curve
    declares.  The groups below are between three and fourteen orders of
    magnitude narrower than the narrowest registered curve, which is what makes
    them the interesting case: they are small enough to check exhaustively --
    every multiplier, against a product built by repeated addition -- which is
    the only way to establish that a ladder is right for all of them rather
    than for the ones a test happened to pick, and they are the only groups
    here where a multiplication is cheap enough to count for every multiplier
    there is.

    Five of the nine sit at the floor itself, of seventeen points up to
    thirty-one, and they are not there for symmetry.  An order that narrow is
    recoded into two digits rather than three or more, which is the only shape
    in which the last addition of a ladder is also the one where both operands
    still carry a ``z`` of one, and that is the one addition formula of this
    module that reads its operands as equal by comparing raw differences rather
    than reduced ones.  Multiplying such a group by the residue
    `equal_operand_residues()` names is therefore the narrowest case there is,
    and it is asserted here rather than reasoned about.

    What stays outside is stated by the tests too, and both exclusions are
    consequences of the recoding rather than thresholds anyone chose.  An order
    of an even number of points cannot be recoded at all, because no multiple
    of an even order changes the parity of a multiplier and the recoding needs
    an odd value.  An order no wider than the widest digit the recoding emits
    cannot either, because the odd multiple that digit names is then a multiple
    of the order, that is the point at infinity, which the affine coordinates a
    table entry holds cannot represent; `SMALLEST_ORDER` is where that stops
    biting.  Both keep the behaviour of releases up to 0.19.1, and neither is a
    group anything can be hidden in: a group of at most sixteen points hands a
    multiplier to a search of at most sixteen tries.
    """

    #: prime order groups over small fields: prime, a, b, the coordinates of a
    #: generator, and the order.  Found by counting the points of every curve
    #: over the primes below 120 and keeping those whose count is one of the
    #: orders wanted; `test_the_groups_are_what_they_claim_to_be` re-checks
    #: every one of those claims here rather than trusting the search.
    GROUPS = (
        (11, 2, 4, 0, 2, 17),
        (13, 0, 2, 1, 4, 19),
        (17, 3, 5, 1, 3, 23),
        (23, 1, 4, 0, 2, 29),
        (23, 5, 1, 0, 1, 31),
        (73, 3, 18, 0, 23, 89),
        (79, 0, 3, 1, 2, 97),
        (83, 2, 28, 0, 32, 101),
        (89, 3, 18, 0, 14, 103),
    )

    #: the same four orders as twisted Edwards groups: prime, a, d, the
    #: coordinates of a point of that order, and the order.  A complete
    #: twisted Edwards curve has a point of order four, so the group is four
    #: times as large as the subgroup used here and ``d`` is a non-square, which
    #: is what keeps the addition formula away from its exceptional cases.  None
    #: of the multiples of these points has a zero coordinate, which matters
    #: because `PointEdwards.__add__()` reads a zero ``x`` or ``x * y`` as the
    #: point at infinity -- true for the identity and, on a group with a
    #: cofactor, for the points of order two and four as well.
    EDWARDS_GROUPS = (
        (53, 1, 27, 4, 27, 17),
        (61, 1, 29, 4, 6, 19),
        (79, 1, 6, 5, 34, 23),
        (97, 1, 30, 2, 15, 29),
        (103, 1, 57, 2, 33, 31),
        (331, 1, 40, 2, 326, 89),
        (353, 1, 57, 3, 309, 97),
        (367, 1, 88, 2, 317, 101),
        (373, 1, 61, 2, 290, 103),
    )

    def group(self, index):
        """Return the curve, the generator coordinates and the order."""
        prime, a, b, x, y, order = self.GROUPS[index]
        return CurveFp(prime, a, b), x, y, order

    def edwards_group(self, index):
        """Return the curve, the point coordinates and the order."""
        prime, a, d, x, y, order = self.EDWARDS_GROUPS[index]
        return CurveEdTw(prime, a, d, h=4), x, y, order

    def edwards_point(self, curve, x, y, order, generator=False):
        """Return the point of `order`, in the coordinates the class wants."""
        return PointEdwards(
            curve,
            x,
            y,
            1,
            x * y % curve.p(),
            order,
            generator=generator,
        )

    def edwards_expected(self, order, window):
        """
        Return the shape and the operation counts of a twisted Edwards group.

        The table and the additions are the ones `expected()` describes.  The
        doublings differ by one whole window: this ladder doubles before every
        digit including the most significant one, where the short Weierstrass
        ladder skips the doublings that would only act on the point at
        infinity.
        """
        digits, entries = fixed_ladder_shape(order, window)
        return (
            digits,
            entries,
            digits + (1 << (window - 1)) - 1,
            digits * window + 1,
        )

    def edwards_reference(self, curve, x, y, order):
        """Return every multiple of the point, by repeated addition."""
        base = self.edwards_point(curve, x, y, order)
        multiples = [INFINITY]
        while len(multiples) <= order:
            multiples.append(multiples[-1] + base)
        return multiples

    def expected(self, order, window):
        """
        Return the shape and the operation counts of a group, derived from the
        order and the width alone.

        The table of a generator holds the odd multiples of a whole window per
        digit position; a multiplication that reads it performs one addition per
        digit and no doubling.  One that has no table builds the odd multiples
        of the point first, which is one doubling for the step between them and
        one addition for each further multiple, and then spends a whole window
        of doublings per digit except before the most significant one, which has
        nothing but the point at infinity to act on.
        """
        digits, entries = fixed_ladder_shape(order, window)
        return (
            digits,
            entries,
            digits + (1 << (window - 1)) - 1,
            (digits - 1) * window + 1,
        )

    def reference(self, curve, x, y, order):
        """Return every multiple of the generator, by repeated addition."""
        base = PointJacobi(curve, x, y, 1, order)
        multiples = [INFINITY]
        while len(multiples) <= order:
            multiples.append(multiples[-1] + base)
        return multiples

    def rule_admits(self, order, window):
        """
        Whether `order` can be recoded at `window`, read off the rule.

        Two conditions, both consequences of the recoding rather than
        thresholds anyone chose, and both written out here from what they mean
        rather than from how `_fixed_window()` tests them, so that the boundary
        the other tests state as a literal is not the implementation agreeing
        with itself:

        * the order has to be odd.  Normalising lands on an odd value by adding
          a multiple of the order to the residue, which cannot change a parity
          unless the order is odd, and `_fixed_digits()` requires an odd input.
        * no odd multiple a digit can name may be a multiple of the order.  A
          ladder answers a digit with that odd multiple of the point, and a
          multiple of the order is the point at infinity, which the two or
          three affine coordinates a table entry holds cannot represent.
        """
        if not order or not order % 2:
            return False
        for digit in range(1, 1 << window, 2):
            if not digit % order:
                return False
        return True

    def test_the_narrowest_order_is_where_the_rule_puts_it(self):
        window = ellipticcurve._MUL_WINDOW
        floor = min(
            order
            for order in range(1, 4000)
            if self.rule_admits(order, window)
        )

        self.assertEqual(floor, SMALLEST_ORDER)
        # the floor is one above the widest digit, and the widest digit is what
        # the width decides, so the two are the same statement
        self.assertEqual(floor, (1 << window) + 1)
        self.assertEqual(
            min(
                order
                for order in range(1, 4000)
                if PointJacobi._fixed_ladder_usable(order)
            ),
            SMALLEST_ORDER,
        )
        # every order the module admits is one the rule admits, and the other
        # way round, up to a few thousand
        for order in range(0, 4000):
            self.assertEqual(
                PointJacobi._fixed_ladder_usable(order),
                self.rule_admits(order, window),
                order,
            )
        # A narrower width would admit more orders and not fewer, its widest
        # digit being smaller, so nothing about this floor is a limit of the
        # recoding itself: it is the floor of the one width the module recodes
        # at.  A narrower width is not used because it costs a ladder more
        # additions per multiplication, and it is not reached for to rescue an
        # order this width refuses either, since a second width would make
        # which width a point is recoded at a property of its order.
        for narrower in range(1, window):
            self.assertEqual(
                min(
                    order
                    for order in range(1, 4000)
                    if self.rule_admits(order, narrower)
                ),
                (1 << narrower) + 1,
                narrower,
            )
            self.assertGreater(floor, (1 << narrower) + 1)

    def test_the_groups_are_what_they_claim_to_be(self):
        for index in range(len(self.GROUPS)):
            curve, x, y, order = self.group(index)
            base = PointJacobi(curve, x, y, 1, order)

            self.assertTrue(curve.contains_point(x, y))
            self.assertEqual(base * order, INFINITY)
            # the order is exact, not just a multiple of the real one: no
            # smaller multiple of the generator is the point at infinity
            multiples = self.reference(curve, x, y, order)
            self.assertEqual(multiples[order], INFINITY)
            for multiple in range(1, order):
                self.assertNotEqual(multiples[multiple], INFINITY)

    def test_the_widths_the_groups_are_recoded_with(self):
        widths = [
            PointJacobi._fixed_window(order)
            for _, _, _, _, _, order in self.GROUPS
        ]

        self.assertEqual(widths, [ellipticcurve._MUL_WINDOW] * 9)
        # and the shape that width gives, as literals: an order of seven bits
        # normalises to at most nine, which needs three whole windows of four,
        # each holding the eight odd multiples a window reaches
        self.assertEqual(self.expected(89, 4), (3, 24, 10, 9))
        self.assertEqual(self.expected(97, 4), (3, 24, 10, 9))
        self.assertEqual(self.expected(101, 4), (3, 24, 10, 9))
        self.assertEqual(self.expected(103, 4), (3, 24, 10, 9))
        # an order at the floor is five bits, normalises to at most seven, and
        # so needs two windows rather than three -- the shape the class
        # docstring calls the narrowest case there is
        for order in (17, 19, 23, 29, 31):
            self.assertEqual(self.expected(order, 4), (2, 16, 9, 5))

    def test_a_narrow_group_builds_a_table_of_the_narrow_shape(self):
        for index in range(len(self.GROUPS)):
            curve, x, y, order = self.group(index)
            window = PointJacobi._fixed_window(order)
            _, entries, _, _ = self.expected(order, window)

            generator = PointJacobi(curve, x, y, 1, order, generator=True)
            self.assertEqual(precompute_table(generator), [])
            generator * 1
            table = precompute_table(generator)

            self.assertEqual(len(table), entries)
            self.assertTrue(PointJacobi._fixed_table_shaped(table, order, 2))
            # a table holding one digit position too few, or one too many, is
            # not a table this order can index
            for wrong in (
                entries - (1 << (window - 1)),
                entries + (1 << (window - 1)),
            ):
                self.assertNotEqual(wrong, entries)
                self.assertFalse(
                    PointJacobi._fixed_table_shaped([(1, 2)] * wrong, order, 2)
                )

    def test_every_multiplier_of_a_narrow_group_is_answered_correctly(self):
        for index in range(len(self.GROUPS)):
            curve, x, y, order = self.group(index)
            multiples = self.reference(curve, x, y, order)
            generator = PointJacobi(curve, x, y, 1, order, generator=True)
            generator * 1

            for scalar in range(order + 3):
                want = multiples[scalar % order]

                self.assertEqual(generator * scalar, want, (order, scalar))
                point = PointJacobi(curve, x, y, 1, order)
                self.assertEqual(point * scalar, want, (order, scalar))

    def test_a_two_digit_ladder_answers_two_equal_operands(self):
        """
        The narrowest shape there is, asserted rather than reasoned about.

        A group at the floor is recoded into two digits, so the last addition
        of its ladder is the second one -- and the second one is the only
        addition where both operands still carry a ``z`` of one.  The formula
        for that case reads its operands as equal by comparing the raw
        difference of their coordinates rather than a reduced one, so a ladder
        that hands it the bare negation of a table entry, congruent to the
        accumulator modulo the field prime but not equal to it as an integer,
        gets the point at infinity back where the product belongs.  No wider
        group reaches that formula with two equal operands, which is why the
        case is stated here and nowhere else.
        """
        window = ellipticcurve._MUL_WINDOW
        checked = 0
        for index in range(len(self.GROUPS)):
            curve, x, y, order = self.group(index)
            digits, _ = fixed_ladder_shape(order, window)
            degenerate = equal_operand_residues(order, window)
            if digits != 2 or not degenerate:
                continue
            multiples = self.reference(curve, x, y, order)
            generator = PointJacobi(curve, x, y, 1, order, generator=True)
            generator * 1

            for residue in degenerate:
                want = multiples[residue]

                self.assertNotEqual(want, INFINITY)
                self.assertEqual(generator * residue, want, (order, residue))
                point = PointJacobi(curve, x, y, 1, order)
                self.assertEqual(point * residue, want, (order, residue))
                checked += 1

        # exactly four of the nine groups are two digits wide and have such a
        # residue: the group of twenty-three points has none, and the four
        # above the floor are three digits wide
        self.assertEqual(checked, 4)

    def test_the_work_of_a_narrow_group_does_not_follow_the_multiplier(self):
        for index in range(len(self.GROUPS)):
            curve, x, y, order = self.group(index)
            window = PointJacobi._fixed_window(order)
            digits, _, table_less_adds, table_less_doubles = self.expected(
                order, window
            )
            generator = PointJacobi(curve, x, y, 1, order, generator=True)
            generator * 1

            # One count for every multiplier there is, the residues
            # `equal_operand_residues()` names included: on a short Weierstrass
            # curve their extra work is entered inside `_add_with_z2_1()` and
            # answered by `_double_with_z_1()`, so neither of the two counted
            # dispatchers moves and this set really is a single pair.
            with_table = set()
            without_table = set()
            for scalar in range(order + 3):
                _, adds, doubles = count_point_operations(
                    PointJacobi, lambda: generator * scalar
                )
                with_table.add((adds, doubles))
                point = PointJacobi(curve, x, y, 1, order)
                _, adds, doubles = count_point_operations(
                    PointJacobi, lambda: point * scalar
                )
                without_table.add((adds, doubles))

            self.assertEqual(with_table, set([(digits, 0)]))
            self.assertEqual(
                without_table, set([(table_less_adds, table_less_doubles)])
            )

    def test_a_narrow_group_hands_the_affine_ladder_over(self):
        # The affine implementation keeps the X9.62 D.3.2 ladder, whose work
        # follows the multiplier, and hands a multiplication over to the Jacobi
        # coordinate one whenever the order allows it.  A narrow order allows it
        # now, so these points get the fixed work too.
        for index in range(len(self.GROUPS)):
            curve, x, y, order = self.group(index)
            window = PointJacobi._fixed_window(order)
            _, _, adds, doubles = self.expected(order, window)
            multiples = self.reference(curve, x, y, order)

            counts = set()
            for scalar in range(order + 3):
                point = Point(curve, x, y, order)
                product, added, doubled = count_point_operations(
                    PointJacobi, lambda: point * scalar
                )

                self.assertEqual(
                    multiples[scalar % order], product, (order, scalar)
                )
                counts.add((added, doubled))

            self.assertEqual(counts, set([(adds, doubles)]))

    def test_the_affine_ladder_is_reached_only_without_a_usable_order(self):
        """
        The X9.62 D.3.2 ladder, counted directly rather than inferred.

        `test_a_narrow_group_hands_the_affine_ladder_over` establishes that a
        point of a usable order is answered with the fixed number of Jacobi
        coordinate operations; this establishes the other half, that the ladder
        it was handed over from is not entered at all in that case.  Counting
        `Point.double()` is what makes it direct: the X9.62 ladder calls it
        once per iteration and the hand-off never calls it, so the count is
        zero exactly when the fall-through was not taken.

        The three orders that do fall through are the three
        `test_which_orders_the_fixed_work_reaches` names, and for each of them
        the count really does follow the multiplier -- one iteration per bit
        of three times it, less the two the ladder starts past -- which is the
        leak the hand-off exists to avoid.  The multipliers below are chosen to
        be multiples of none of the three orders, so that none of them is
        answered by the ladder's own multiple-of-the-order shortcut and every
        one of them is really walked.
        """
        order = int(NIST256p.order)
        coord_x = NIST256p.generator.x()
        coord_y = NIST256p.generator.y()
        curve = NIST256p.curve
        multipliers = (3, 251, 12347, 1 << 200)

        def doublings(point_order, scalar):
            point = Point(curve, coord_x, coord_y, point_order)
            _, profile = count_formula_calls(
                Point, ("double",), lambda: point * scalar
            )
            return dict(profile)["double"]

        # a usable order enters it for no multiplier at all
        self.assertEqual(
            [doublings(order, scalar) for scalar in multipliers], [0] * 4
        )
        # and the three that are not usable enter it for every multiplier, at a
        # count that is `bit_length(3 * scalar) - 2` and so follows the
        # multiplier and nothing else -- not even the order, the three of them
        # spending exactly the same
        for unusable in (None, 2 * order, SMALLEST_ORDER - 2):
            counts = [doublings(unusable, scalar) for scalar in multipliers]

            self.assertEqual(counts, [2, 8, 14, 200], unusable)
            self.assertEqual(
                counts,
                [bit_length(3 * scalar) - 2 for scalar in multipliers],
                unusable,
            )
        # none of those multipliers is a multiple of any of those orders, so
        # none of the counts above was the ladder answering one early
        for unusable in (2 * order, SMALLEST_ORDER - 2):
            for scalar in multipliers:
                self.assertTrue(scalar % unusable, (unusable, scalar))

    def test_what_the_narrow_groups_looked_like_before(self):
        # The same points without an order keep the multiplier-driven ladder,
        # and its work varies with the multiplier -- which is what the tests
        # above establish is gone once the order is known.  Without this the
        # counts above could be constant because these groups are too small for
        # anything to vary in.
        for index in range(len(self.GROUPS)):
            curve, x, y, order = self.group(index)
            counts = set()
            for scalar in range(1, order):
                point = PointJacobi(curve, x, y, 1)
                _, adds, doubles = count_point_operations(
                    PointJacobi, lambda: point * scalar
                )
                counts.add((adds, doubles))

            self.assertGreater(len(counts), 1, order)

    def test_the_edwards_groups_are_what_they_claim_to_be(self):
        for index in range(len(self.EDWARDS_GROUPS)):
            curve, x, y, order = self.edwards_group(index)
            multiples = self.edwards_reference(curve, x, y, order)

            self.assertTrue(curve.contains_point(x, y))
            self.assertEqual(multiples[order], INFINITY)
            for multiple in range(1, order):
                self.assertNotEqual(multiples[multiple], INFINITY)
                # a zero coordinate would be read as the point at infinity by
                # the addition, so the reference above would be wrong
                self.assertNotEqual(multiples[multiple].x() % curve.p(), 0)
                self.assertNotEqual(multiples[multiple].y() % curve.p(), 0)

    def test_the_shapes_the_edwards_groups_are_recoded_into(self):
        widths = [
            PointEdwards._fixed_window(order)
            for _, _, _, _, _, order in self.EDWARDS_GROUPS
        ]

        self.assertEqual(widths, [ellipticcurve._MUL_WINDOW] * 9)
        # the digit count and the table are shared with the short Weierstrass
        # ladder; only the doublings differ, by the one window this ladder does
        # not skip
        self.assertEqual(self.edwards_expected(89, 4), (3, 24, 10, 13))
        self.assertEqual(self.edwards_expected(103, 4), (3, 24, 10, 13))
        for order in (17, 19, 23, 29, 31):
            self.assertEqual(self.edwards_expected(order, 4), (2, 16, 9, 9))

    def test_a_narrow_edwards_group_gets_the_fixed_work(self):
        for index in range(len(self.EDWARDS_GROUPS)):
            curve, x, y, order = self.edwards_group(index)
            window = PointEdwards._fixed_window(order)
            digits, entries, adds, doubles = self.edwards_expected(
                order, window
            )
            multiples = self.edwards_reference(curve, x, y, order)

            generator = self.edwards_point(curve, x, y, order, generator=True)
            self.assertEqual(precompute_table(generator), [])
            generator * 1
            table = precompute_table(generator)
            self.assertEqual(len(table), entries)
            self.assertTrue(PointEdwards._fixed_table_shaped(table, order, 3))

            # the one residual `equal_operand_residues()` describes: a twisted
            # Edwards addition of two equal operands dispatches back through
            # the doubling formula, so those residues pay one counted doubling
            # more.  Asserted per multiplier rather than absorbed into a set,
            # so that both the count and which multipliers get it are exact.
            degenerate = equal_operand_residues(order, window)
            self.assertLessEqual(len(degenerate), 2)
            for scalar in range(order + 3):
                want = multiples[scalar % order]
                extra = int(scalar % order in degenerate)

                product, added, doubled = count_point_operations(
                    PointEdwards, lambda: generator * scalar
                )
                self.assertEqual(product, want, (order, scalar))
                self.assertEqual(
                    (added, doubled), (digits, extra), (order, scalar)
                )

                point = self.edwards_point(curve, x, y, order)
                product, added, doubled = count_point_operations(
                    PointEdwards, lambda: point * scalar
                )
                self.assertEqual(product, want, (order, scalar))
                self.assertEqual(
                    (added, doubled), (adds, doubles + extra), (order, scalar)
                )

    def test_which_orders_the_fixed_work_reaches(self):
        """
        The whole inventory of what is left on the old ladder, in one place.

        Three conditions on the order, and nothing else, decide it, and all
        three are consequences of the recoding rather than thresholds anyone
        chose: an order that is not known, one of an even number of points, and
        one no larger than the largest digit the recoding emits.  They are
        written out here from what they mean, so a fourth condition appearing
        in the module -- a floor picked for a reason the recoding does not
        force, a curve singled out, anything reading the multiplier -- fails
        this test rather than passing quietly.

        The three point classes share the decision, so it is asserted for all
        three, and no order any registered curve declares is refused by it.

        `AbstractPoint._fixed_ladder_usable()` is the whole of that decision
        and it is handed nothing but the order -- there is no multiplier for it
        to read, which is a stronger statement than any assertion about what it
        does with one, and `TestMultiplierNormalisation` covers the one step
        that is handed the multiplier.
        """

        def documented(order):
            if not order:
                return "the order is not known"
            if not int(order) % 2:
                return "the order is even"
            if int(order) <= (1 << ellipticcurve._MUL_WINDOW) - 1:
                return "the order is no larger than the largest digit"
            return None

        orders = list(range(0, 2001))
        orders.append(None)
        orders.extend(int(curve.order) for curve in curves)
        for order in orders:
            reason = documented(order)

            for point_class in (PointJacobi, PointEdwards, Point):
                self.assertEqual(
                    point_class._fixed_ladder_usable(order),
                    reason is None,
                    (order, reason, point_class),
                )

        # the decision is handed the order and nothing else, so no multiplier
        # can reach it: the class it is bound to, and the order
        code = PointJacobi._fixed_ladder_usable.__code__
        self.assertEqual(
            code.co_varnames[: code.co_argcount], ("cls", "order")
        )

        # and every curve this library registers is on the fixed work side of
        # that line, the narrowest of them declaring an order of 110 bits
        for curve in curves:
            self.assertIsNone(documented(int(curve.order)))
            self.assertTrue(
                PointJacobi._fixed_ladder_usable(int(curve.order)), curve.name
            )
        self.assertEqual(
            min(bit_length(int(curve.order)) for curve in curves), 110
        )

    def test_an_even_order_keeps_the_multiplier_driven_ladder(self):
        # No multiple of an even order changes the parity of a multiplier, so
        # there is no odd value congruent to an even multiplier for the
        # recoding to work on, whatever the digit width.  Such a group is not a
        # valid set of ECDSA domain parameters -- both ECDSA and SEC 1 require a
        # prime generator order -- and it keeps the behaviour of releases up to
        # 0.19.1, which is what is asserted here.
        for order in (2 * SMALLEST_ORDER, 2 * int(NIST256p.order), 30, 256):
            self.assertEqual(PointJacobi._fixed_window(order), 0)
            self.assertEqual(PointJacobi._fixed_ladder_usable(order), False)

        # a group of an even order really does exist and really is multiplied
        # the old way: the curve ``y**2 = x**3 + x + 1`` over the field of 23
        # has 28 points, and (0, 1) generates all of them
        curve = CurveFp(23, 1, 1)
        point = PointJacobi(curve, 0, 1, 1, 28, generator=True)
        self.assertEqual(point * 28, INFINITY)
        for multiple in range(1, 28):
            self.assertNotEqual(point * multiple, INFINITY)
        self.assertEqual(precompute_table(point), [])

        counts = set()
        for scalar in range(1, 28):
            _, adds, doubles = count_point_operations(
                PointJacobi, lambda: point * scalar
            )
            counts.add((adds, doubles))
        self.assertGreater(len(counts), 1)


class TestECDHKeyAgreement(unittest.TestCase):
    """
    The ECDH exposure of the advisory, and the honest limit of this change.

    The advisory names key agreement alongside signing, and the secret there is
    worse than a nonce: it is the long term private key, reused for every
    exchange, so an attacker gets to accumulate observations of one value
    instead of one observation each of many.  The multiplication that carries
    it is the remote public point multiplied by that key.

    Whether that multiplication takes the fixed work path turns on one thing
    only: whether the point reports its order.  A point built by multiplying a
    curve generator does -- `keys.SigningKey.get_verifying_key()` builds its
    public point that way, and a product reports the order of the point it came
    from -- so an exchange against such a point costs what `table_less_shape()`
    says, whatever the private key is.  None of the public point encodings
    carries an order, though, so a point handed to
    `keys.VerifyingKey.from_string()` or to one of its DER and PEM siblings
    reports none, and a multiplication then has nothing to normalise a
    multiplier against.  Such an exchange keeps the ladder of releases up to
    0.19.1, whose number of doublings is exactly the bit length of the private
    key.

    That second case is a residual exposure rather than a fixed defect, and it
    is asserted here as squarely as the fixed cost is: `SECURITY.md`, `README`
    and `NEWS` all name it, and a test suite that quietly left it out would
    give a reader no way to check what they say.  Closing it would mean
    attaching an order where a point is decoded, in `ecdsa.keys` or
    `ecdsa.ecdsa.Public_key`, and the remediation this belongs to is confined
    to the scalar multiplication and nonce handling paths.

    The exchanges are driven exactly as a caller would drive them: keys are
    generated, encoded to bytes where the case calls for it, decoded again and
    exchanged, and the only instrumentation is the operation counter around the
    exchange.
    """

    # every registered curve type that ECDH accepts: the curve the advisory
    # names, another 256 bit curve, a larger one, and SECP112r2, the one
    # registered curve whose cofactor is not one.  Edwards curves are not
    # included because `VerifyingKey.from_string()` routes them to
    # `eddsa.PublicKey` and `ECDH` refuses them.
    CURVES = (NIST256p, SECP256k1, BRAINPOOLP384r1, SECP112r2)

    def private_key_widths(self, curve):
        """Bit widths of long term private key to exchange under."""
        top = bit_length(int(curve.order))
        return [width for width in (64, 128, top - 1, top) if 1 < width <= top]

    def local_key(self, curve, width):
        """A signing key whose private scalar is exactly `width` bits wide."""
        return SigningKey.from_secret_exponent(
            (1 << (width - 1)) + 12345, curve=curve
        )

    def exchange_counts(self, curve, remote):
        """
        Return the operation counts of an exchange per private key width.

        One entry per width in `private_key_widths()`, each the ``(additions,
        doublings)`` of the multiplication `ECDH.generate_sharedsecret_bytes()`
        performs, plus the secret it produced so that correctness is asserted
        from the same run that produced the counts.
        """
        results = []
        for width in self.private_key_widths(curve):
            exchange = ECDH(
                curve=curve, private_key=self.local_key(curve, width)
            )
            exchange.load_received_public_key(remote)
            secret, additions, doublings = count_point_operations(
                point_class_of(curve), exchange.generate_sharedsecret_bytes
            )
            results.append(((additions, doublings), secret))
        return results

    def assert_exchange_cost_is_fixed(self, curve):
        """
        Assert one operation count across every private key width.

        The count asserted is the one of the ladder without a multiplication
        table, because the remote point is not a curve generator and so builds
        none.  Before this change every width below produced a count of its
        own, the doubling count being the bit length of the private key.
        """
        expected = table_less_shape(curve)
        remote = SigningKey.generate(curve=curve).get_verifying_key()
        # the point reports the order of the group, which is the whole of what
        # sends the exchange down the ladder whose cost is fixed
        self.assertEqual(remote.pubkey.point.order(), curve.order)

        counts = self.exchange_counts(curve, remote)
        self.assertEqual(sorted(set(count for count, _ in counts)), [expected])
        # more than one width was actually exchanged under, so the equality
        # above is an invariance and not a single measurement
        self.assertGreater(len(counts), 2)
        # and every exchange produced a secret of the size the curve gives
        for _, secret in counts:
            self.assertEqual(len(secret), curve.baselen)

    def test_exchange_cost_on_nist256p(self):
        self.assert_exchange_cost_is_fixed(NIST256p)

    def test_exchange_cost_on_secp256k1(self):
        self.assert_exchange_cost_is_fixed(SECP256k1)

    def test_exchange_cost_on_brainpoolp384r1(self):
        self.assert_exchange_cost_is_fixed(BRAINPOOLP384r1)

    def test_exchange_cost_on_a_curve_whose_cofactor_is_not_one(self):
        """SECP112r2, the one registered curve of cofactor other than one."""
        self.assertNotEqual(SECP112r2.curve.cofactor(), 1)
        self.assert_exchange_cost_is_fixed(SECP112r2)

    def test_the_fixed_exchange_cost_is_the_count_it_should_be(self):
        """
        The count `assert_exchange_cost_is_fixed()` compares against.

        Stated as literals rather than derived, so that a change to either the
        expectation helper or to the ladder has to be deliberate.  Sixty five
        digits of four bits for a 256 bit order, seven more additions to build
        the eight odd multiples of the point, and a whole window of doublings
        between consecutive digits with the one before the most significant
        digit skipped, plus the one that steps between odd multiples.
        """
        self.assertEqual(table_less_shape(NIST256p), (72, 257))
        self.assertEqual(table_less_shape(SECP256k1), (72, 257))
        self.assertEqual(table_less_shape(BRAINPOOLP384r1), (104, 385))
        self.assertEqual(table_less_shape(SECP112r2), (35, 109))

    def test_a_decoded_public_key_reports_no_order(self):
        """
        Why the exchange below is not the exchange above.

        No public point encoding carries an order, and none of the decoders
        invents one, whether or not the caller asked for the point to be
        validated.  This is read from the point rather than assumed, because
        every claim about the ladder a decoded key takes rests on it.
        """
        for curve in self.CURVES:
            raw = SigningKey.generate(curve=curve).get_verifying_key()
            for validate_point in (True, False):
                decoded = VerifyingKey.from_string(
                    raw.to_string(),
                    curve=curve,
                    validate_point=validate_point,
                )
                self.assertIsNone(decoded.pubkey.point.order())
                # and it builds no multiplication table either, not being
                # marked as a curve generator
                self.assertEqual(
                    decoded.pubkey.point._PointJacobi__precompute, []
                )
                self.assertFalse(
                    PointJacobi._fixed_ladder_usable(
                        decoded.pubkey.point.order()
                    )
                )

    def test_an_exchange_with_a_decoded_key_keeps_the_old_ladder(self):
        """
        The residual exposure, measured rather than described.

        A decoded remote point reports no order, so the multiplication by the
        long term private key is the non-adjacent form ladder of releases up to
        0.19.1, and its number of doublings is exactly the bit length of that
        key.  This is what `SECURITY.md` discloses; the assertion is the exact
        count, so the disclosure cannot drift from the code.
        """
        for curve in (NIST256p, BRAINPOOLP384r1):
            remote = VerifyingKey.from_string(
                SigningKey.generate(curve=curve)
                .get_verifying_key()
                .to_string(),
                curve=curve,
                validate_point=False,
            )
            doublings = []
            for width in self.private_key_widths(curve):
                exchange = ECDH(
                    curve=curve, private_key=self.local_key(curve, width)
                )
                exchange.load_received_public_key(remote)
                secret, _, count = count_point_operations(
                    point_class_of(curve),
                    exchange.generate_sharedsecret_bytes,
                )
                self.assertEqual(len(secret), curve.baselen)
                self.assertEqual(count, width)
                doublings.append(count)
            # the count is a different one for every width, which is the leak
            self.assertEqual(doublings, self.private_key_widths(curve))
            self.assertEqual(
                len(set(doublings)), len(self.private_key_widths(curve))
            )

    def test_the_same_key_exchanges_at_both_costs(self):
        """
        One private key, two remote points, two costs.

        The same long term secret is multiplied by a point that reports the
        order and by the very same point decoded from its encoding, and the two
        multiplications cost differently: the fixed count in the first case and
        a count that follows the secret in the second.  Nothing about the
        secret decides which path is taken -- only the point does.
        """
        curve = NIST256p
        peer = SigningKey.generate(curve=curve).get_verifying_key()
        decoded = VerifyingKey.from_string(peer.to_string(), curve=curve)
        secrets = []
        counts = []
        for remote in (peer, decoded):
            exchange = ECDH(
                curve=curve, private_key=self.local_key(curve, 128)
            )
            exchange.load_received_public_key(remote)
            secret, additions, doublings = count_point_operations(
                point_class_of(curve), exchange.generate_sharedsecret_bytes
            )
            secrets.append(secret)
            counts.append((additions, doublings))
        # the same secret either way: the two points are the same point
        self.assertEqual(secrets[0], secrets[1])
        self.assertEqual(counts[0], table_less_shape(curve))
        self.assertEqual(counts[1][1], 128)
        self.assertNotEqual(counts[0], counts[1])

    def test_both_peers_agree_on_the_secret(self):
        """The exchange still computes what it computed before."""
        for curve in self.CURVES:
            first = SigningKey.generate(curve=curve)
            second = SigningKey.generate(curve=curve)
            secrets = []
            for mine, theirs in ((first, second), (second, first)):
                remote = VerifyingKey.from_string(
                    theirs.get_verifying_key().to_string(),
                    curve=curve,
                    validate_point=False,
                )
                exchange = ECDH(curve=curve, private_key=mine)
                exchange.load_received_public_key(remote)
                secrets.append(exchange.generate_sharedsecret_bytes())
            self.assertEqual(secrets[0], secrets[1])

    def test_a_product_reports_what_it_always_did(self):
        """
        What a multiplication answers with is unchanged.

        The product of a point that reports an order reports that same order,
        and is not marked as a curve generator, so it builds no multiplication
        table of its own.  That is what `keys.SigningKey.get_verifying_key()`
        relies on, and it is why the public point of a freshly built key takes
        the fixed ladder at an exchange.
        """
        for curve in self.CURVES:
            key = SigningKey.generate(curve=curve)
            point = key.get_verifying_key().pubkey.point
            self.assertEqual(point.order(), curve.order)
            self.assertEqual(point._PointJacobi__precompute, [])
            product = point * 7
            self.assertEqual(product.order(), curve.order)
            self.assertEqual(product._PointJacobi__precompute, [])
            self.assertEqual(
                product, curve.generator * (7 * key.privkey.secret_multiplier)
            )


class TestSignedDigitSymmetry(unittest.TestCase):
    """
    The sign of a digit costs the same as its absence of one (Defect #7).

    The recoding of a multiplier emits signed digits, and a negative one asks
    the ladder for the negation of the table entry it selected -- one field wide
    negation on the Weierstrass points, two on the twisted Edwards ones, where
    the product of the affine coordinates is negated along with the x
    coordinate.  How many of the digits are negative follows the multiplier
    (between 18 and 27 of the 65 digits of a NIST256p multiplier, and between 12
    and 30 of the 41 of a SECP160r1 one, over the multipliers this class uses),
    so doing that work only on the negative ones would put a quantity derived
    from the secret back into the run time -- the same shape of leak the number
    of additions used to carry.

    The ladders therefore derive both polarities of the selected entry for every
    digit and pick the answer out by index.  Asserted here by counting the
    negations rather than by timing anything: the count has to be a constant
    that follows the number of digit positions, which is public, while the
    number of negative digits varies.  Both fixed work paths are covered, since
    a secret reaches both -- a nonce the table of a generator, an ECDH private
    key a point without one.
    """

    #: negations a digit asks for, by point class
    PER_DIGIT = {"PointJacobi": 1, "PointEdwards": 2}

    CURVES = (NIST256p, BRAINPOOLP384r1, SECP160r1, Ed25519)

    def scalars(self, order):
        """Multipliers spanning the edges and every width in between."""
        order = int(order)
        scalars = [1, 2, 3, 12345, order - 1, order - 7, order // 3]
        for width in stratified_widths(order):
            scalars.extend(scalars_of_width(width, 2, seed=11))
        return scalars

    def negative_digit_counts(self, order):
        """How many digits of each multiplier of `self.scalars()` are negative.

        Derived from the recoding itself, which is what makes the constancy of
        the negation count below a statement rather than a coincidence: if this
        were constant too there would be nothing to hide.
        """
        order = int(order)
        window = ellipticcurve._MUL_WINDOW
        counts = []
        for scalar in self.scalars(order):
            canonical = canonical_scalar(scalar, order)
            digits = PointJacobi._fixed_digits(
                canonical,
                PointJacobi._fixed_digit_count(order, window),
                window,
            )
            counts.append(sum(1 for digit in digits if digit < 0))
        return counts

    def assert_negations_are_constant(self, curve, precomputed):
        order = int(curve.order)
        digits, _ = fixed_ladder_shape(order)
        per_digit = self.PER_DIGIT[point_class_of(curve).__name__]
        expected = digits * per_digit

        # the quantity that must not reach the run time really does vary
        varying = self.negative_digit_counts(order)
        self.assertGreater(len(set(varying)), 1)
        self.assertGreater(min(varying), 0)
        self.assertLess(max(varying), digits)

        for scalar in self.scalars(order):
            if precomputed:
                point = warm_generator(curve)
            else:
                point = rebuilt_generator(curve, False)

            product, negations = count_coordinate_negations(point, scalar)

            self.assertEqual(negations, expected, "multiplier %d" % scalar)
            # and the ladder still returned the right point, so the index
            # selection picked the polarity the digit asked for
            self.assertEqual(product, curve.generator * scalar)

    def test_negations_are_constant_on_nist256p(self):
        self.assert_negations_are_constant(NIST256p, True)
        self.assert_negations_are_constant(NIST256p, False)

    def test_negations_are_constant_on_brainpoolp384r1(self):
        self.assert_negations_are_constant(BRAINPOOLP384r1, True)
        self.assert_negations_are_constant(BRAINPOOLP384r1, False)

    def test_negations_are_constant_on_secp160r1(self):
        self.assert_negations_are_constant(SECP160r1, True)
        self.assert_negations_are_constant(SECP160r1, False)

    def test_negations_are_constant_on_ed25519(self):
        """Two negations per digit, not one, on this curve type."""
        self.assert_negations_are_constant(Ed25519, True)
        self.assert_negations_are_constant(Ed25519, False)

    def test_the_negation_counts_of_this_implementation(self):
        """
        The exact figures, so a change to either ladder is caught here.

        One negation per digit on the Weierstrass points and two on the twisted
        Edwards ones, times the number of digit positions of the curve.
        """
        self.assertEqual(ellipticcurve._MUL_WINDOW, 4)
        for curve, expected in (
            (NIST256p, 65),
            (BRAINPOOLP384r1, 97),
            (SECP160r1, 41),
            (Ed25519, 128),
        ):
            _, negations = count_coordinate_negations(
                warm_generator(curve), 12345
            )
            self.assertEqual(negations, expected, curve.name)
            _, negations = count_coordinate_negations(
                rebuilt_generator(curve, False), 12345
            )
            self.assertEqual(negations, expected, curve.name)

    def test_the_counter_counts_what_it_claims_to(self):
        """
        The instrument itself, so a silent zero cannot pass for a constant.

        A `NegationCounter` holds the value it was given, counts a negation and
        answers with the plain integer type, so nothing computed from one is
        counted twice.
        """
        NegationCounter.counted[0] = 0
        value = NegationCounter(1 << 300)

        self.assertEqual(value, 1 << 300)
        self.assertEqual(NegationCounter.counted[0], 0)
        self.assertEqual(-value, -(1 << 300))
        self.assertEqual(NegationCounter.counted[0], 1)
        self.assertEqual(type(-value), _INT_BASE)
        self.assertEqual(NegationCounter.counted[0], 2)
        # arithmetic answers with the plain type, so a derived value is not
        # counted when it is negated in turn
        self.assertEqual(type(value + 1), _INT_BASE)
        self.assertEqual(-(value + 1), -(1 << 300) - 1)
        self.assertEqual(NegationCounter.counted[0], 2)


class TestFixedDigitRecoding(unittest.TestCase):
    """
    The recoding that fixes the number of point operations.

    `AbstractPoint._fixed_digits()` re-expresses a multiplier as a fixed length
    sequence of signed digits, none of which is zero.  Both halves of that
    matter: the fixed length is what stops the number of iterations of a ladder
    following the multiplier (Defect #3) and the absence of a zero digit is
    what stops the number of additions following its Hamming weight (Defect
    #2), since a ladder can then add one table entry per digit unconditionally
    instead of adding one only when the digit is not zero.

    `AbstractPoint._naf()`, the recoding this one is added next to rather than
    in place of, is asserted to be untouched: `mul_add()` still uses it, and
    `mul_add()` is the verification path, which handles no secret and is
    deliberately left as it was.
    """

    CURVES = (
        NIST256p,
        SECP256k1,
        BRAINPOOLP256r1,
        BRAINPOOLP384r1,
        BRAINPOOLP512r1,
        SECP160r1,
        Ed25519,
    )

    def digits_of(self, scalar, order, window=None):
        if window is None:
            window = ellipticcurve._MUL_WINDOW
        count = PointJacobi._fixed_digit_count(order, window)
        return PointJacobi._fixed_digits(
            canonical_scalar(scalar, order), count, window
        )

    def multipliers_of_every_width(self, order):
        """Multipliers spanning every width a nonce of this curve can have."""
        order = int(order)
        scalars = [0, 1, 2, order - 1, order, order + 1, 2 * order]
        for width in stratified_widths(order):
            scalars.extend(scalars_of_width(width, 2, seed=6))
        return scalars

    def test_no_digit_is_ever_zero(self):
        """The property the addition count of a ladder rests on."""
        for curve in self.CURVES:
            order = int(curve.order)
            for scalar in self.multipliers_of_every_width(order):
                digits = self.digits_of(scalar, order)
                self.assertNotIn(0, digits)

    def test_every_digit_is_odd_and_fits_the_window(self):
        """
        Odd, and narrower than a window.

        Odd is what keeps a digit away from zero at every step of the
        recurrence, and the bound is what lets a table hold only the odd
        multiples a digit can select rather than all of them.
        """
        for curve in self.CURVES:
            order = int(curve.order)
            top = 1 << ellipticcurve._MUL_WINDOW
            for scalar in self.multipliers_of_every_width(order):
                for digit in self.digits_of(scalar, order):
                    self.assertEqual(abs(digit) % 2, 1)
                    self.assertLess(abs(digit), top)

    def test_the_number_of_digits_follows_the_order_alone(self):
        """
        Every multiplier of a curve recodes to the same number of digits.

        This is the assertion the fixed iteration count of the ladders reduces
        to, and it is stated over multipliers ranging from zero to twice the
        order and over every bit width in between.
        """
        for curve in self.CURVES:
            order = int(curve.order)
            expected = PointJacobi._fixed_digit_count(
                order, ellipticcurve._MUL_WINDOW
            )
            lengths = set()
            for scalar in self.multipliers_of_every_width(order):
                lengths.add(len(self.digits_of(scalar, order)))
            self.assertEqual(sorted(lengths), [expected])

    def test_the_number_of_digits_is_rounded_up(self):
        """
        A partial window at the top still gets a digit of its own.

        A count that truncated instead of rounding up would be one digit short
        whenever two bits wider than the order is not a whole number of
        windows, and would leave the top bits of a canonical multiplier
        unrepresented.  SECP112r2 and Ed448 are the two curves here where it
        does divide evenly, so both outcomes are covered, and the test asserts
        that both really are reached rather than trusting that they are.
        """
        divided_evenly = set()
        for curve in self.CURVES + (SECP112r2, Ed448):
            order = int(curve.order)
            width = bit_length(order) + 2
            truncated = width // ellipticcurve._MUL_WINDOW
            count = PointJacobi._fixed_digit_count(
                order, ellipticcurve._MUL_WINDOW
            )
            self.assertEqual(count, -(-width // ellipticcurve._MUL_WINDOW))
            if width % ellipticcurve._MUL_WINDOW:
                self.assertEqual(count, truncated + 1)
                divided_evenly.add(False)
            else:
                self.assertEqual(count, truncated)
                divided_evenly.add(True)
            # wide enough for every canonical multiplier, which is the
            # precondition of the recoding, and not one digit wider
            self.assertGreaterEqual(count * ellipticcurve._MUL_WINDOW, width)
            self.assertLess((count - 1) * ellipticcurve._MUL_WINDOW, width)
        self.assertEqual(sorted(divided_evenly), [False, True])

    def test_the_digits_reconstruct_the_canonical_multiplier(self):
        """
        The correctness oracle: the digits are a faithful re-encoding.

        The digits come out least significant first, so the value they stand
        for is the sum of each one shifted by its position times the window.
        """
        for curve in self.CURVES:
            order = int(curve.order)
            for scalar in self.multipliers_of_every_width(order):
                canonical = canonical_scalar(scalar, order)
                digits = self.digits_of(scalar, order)
                total = 0
                for position, digit in enumerate(digits):
                    total += digit << (position * ellipticcurve._MUL_WINDOW)
                self.assertEqual(total, canonical)
                self.assertEqual(total % order, scalar % order)

    def test_the_digits_of_a_multiplier_are_always_the_same(self):
        order = int(NIST256p.order)
        for scalar in self.multipliers_of_every_width(order):
            self.assertEqual(
                self.digits_of(scalar, order), self.digits_of(scalar, order)
            )

    def test_the_digits_survive_a_change_of_integer_backend(self):
        """
        A multiplier that has been through `int()` recodes to the same digits.

        The recoding coerces its argument with `int()` before reading its bits,
        both because creating gmp objects costs more than the arithmetic they
        save at this size and so that the digits do not depend on which of the
        integer implementations this module can be built on is in use.  Whether
        that is the pure Python one or either gmpy release is deliberately not
        asserted, as the continuous integration exercises all three.
        """
        order = int(NIST256p.order)
        count = PointJacobi._fixed_digit_count(
            order, ellipticcurve._MUL_WINDOW
        )
        for scalar in self.multipliers_of_every_width(order):
            canonical = canonical_scalar(scalar, order)
            self.assertEqual(
                PointJacobi._fixed_digits(
                    canonical, count, ellipticcurve._MUL_WINDOW
                ),
                PointJacobi._fixed_digits(
                    int(canonical), count, ellipticcurve._MUL_WINDOW
                ),
            )

    def test_a_recoding_with_a_negative_digit_still_multiplies_correctly(self):
        """
        The sign of a digit is applied by negating a table entry.

        A recoding of a canonical multiplier that contains a negative digit is
        the ordinary case rather than a corner one, so the multiplication it
        drives has to come out right: the ladders negate the coordinate the
        addition formula needs negated and add the same table entry either way.
        """
        for curve in (SECP160r1, NIST256p, Ed25519):
            order = int(curve.order)
            generator = warm_generator(curve)
            table_less = rebuilt_generator(curve, generator=False)
            found_negative = False
            for scalar in self.multipliers_of_every_width(order):
                if not min(self.digits_of(scalar, order)) < 0:
                    continue
                found_negative = True
                if not scalar % order:
                    continue
                self.assertEqual(generator * scalar, table_less * scalar)
                self.assertEqual(
                    generator * scalar, generator * (scalar % order)
                )
            self.assertTrue(found_negative)

    def test_the_digits_of_the_narrowest_canonical_multiplier(self):
        """
        A multiplier of zero recodes to a full length sequence too.

        Zero is the narrowest thing a caller can hand a ladder, and it is also
        the multiplier whose canonical form is the narrowest of all: the order
        itself, which is the lower end of the interval every canonical
        multiplier comes from.  The recoding of it is still as long as any
        other, which is what makes a multiplication by zero cost what every
        other multiplication costs even though the value being recoded is at
        its narrowest.
        """
        for curve in (SECP160r1, NIST256p, Ed25519):
            order = int(curve.order)
            expected = PointJacobi._fixed_digit_count(
                order, ellipticcurve._MUL_WINDOW
            )
            digits = self.digits_of(0, order)
            self.assertEqual(len(digits), expected)
            self.assertNotIn(0, digits)
            total = 0
            for position, digit in enumerate(digits):
                total += digit << (position * ellipticcurve._MUL_WINDOW)
            self.assertEqual(total, canonical_scalar(0, order))
            self.assertEqual(total, order)
            self.assertEqual(total % order, 0)
            self.assertEqual(total % 2, 1)
            self.assertEqual(bit_length(total), bit_length(order))

    def test_a_window_of_one_degenerates_into_a_signed_expansion(self):
        """
        The recoding at its narrowest, where every digit is plus or minus one.

        Asserted with the window passed explicitly, so that the shape of the
        recoding is pinned independently of the width this module happens to be
        built with.
        """
        order = int(SECP160r1.order)
        canonical = canonical_scalar(12345, order)
        count = PointJacobi._fixed_digit_count(order, 1)
        digits = PointJacobi._fixed_digits(canonical, count, 1)

        self.assertEqual(count, bit_length(order) + 2)
        self.assertEqual(len(digits), count)
        self.assertEqual(sorted(set(digits)), [-1, 1])
        total = 0
        for position, digit in enumerate(digits):
            total += digit << position
        self.assertEqual(total, canonical)

    def test_every_digit_position_is_a_whole_window_wide(self):
        """
        The most significant position is as wide as every other one.

        The bits a canonical multiplier fits in do not divide into whole
        windows in general, so the most significant position covers fewer of
        them than the others -- but it still holds the odd multiples of a whole
        window, and the ladder still selects one of them with the same work it
        spends on any other position.  Trimming that position to the bits it
        actually covers would make the number of table entries, and the number
        of additions that builds them, differ between the most significant
        position and the rest.
        """
        window = ellipticcurve._MUL_WINDOW
        for curve in self.CURVES:
            order = int(curve.order)
            digits, entries = fixed_ladder_shape(order)

            # the positions cover the width, using the fewest whole windows
            self.assertGreaterEqual(digits * window, bit_length(order) + 2)
            self.assertLess((digits - 1) * window, bit_length(order) + 2)
            # and every one of them, the most significant included, holds the
            # odd multiples a whole window reaches
            self.assertEqual(entries, digits * (1 << (window - 1)))
            self.assertEqual(entries % digits, 0)

    def test_the_non_adjacent_form_is_still_there_and_unchanged(self):
        """
        `_naf()` is not replaced, because `mul_add()` still uses it.

        `mul_add()` is the verification path.  It handles only values anyone
        holding the signature can compute, the attack does not reach it, and it
        is deliberately left exactly as it was -- which it cannot be if the
        recoding it drives its ladder with is taken away.
        """
        self.assertEqual(PointJacobi._naf(0), [])
        self.assertEqual(PointJacobi._naf(1), [1])
        self.assertEqual(PointJacobi._naf(5), [1, 0, 1])
        self.assertEqual(PointJacobi._naf(7), [-1, 0, 0, 1])
        self.assertEqual(PointJacobi._naf(255), [-1, 0, 0, 0, 0, 0, 0, 0, 1])
        # a zero digit, which is the whole difference between this recoding and
        # the fixed length one, and what let the number of additions of a
        # ladder driven by it follow the multiplier
        self.assertIn(0, PointJacobi._naf(5))
        for multiplicand in range(1, 200):
            digits = PointJacobi._naf(multiplicand)
            total = 0
            for position, digit in enumerate(digits):
                total += digit << position
            self.assertEqual(total, multiplicand)

    @settings(**NO_OLD_SETTINGS)
    @given(st.integers(min_value=0, max_value=int(NIST256p.order) * 3))
    def test_the_recoding_of_an_arbitrary_multiplier(self, multiplicand):
        """Every property above, over multipliers Hypothesis picks."""
        order = int(NIST256p.order)
        window = ellipticcurve._MUL_WINDOW
        count = PointJacobi._fixed_digit_count(order, window)
        canonical = canonical_scalar(multiplicand, order)
        digits = PointJacobi._fixed_digits(canonical, count, window)

        self.assertEqual(len(digits), count)
        total = 0
        for position, digit in enumerate(digits):
            self.assertEqual(abs(digit) % 2, 1)
            self.assertLess(abs(digit), 1 << window)
            total += digit << (position * window)
        self.assertEqual(total, canonical)


class TestCanonicalScalar(unittest.TestCase):
    """
    Normalising a multiplier before any work is chosen from it (Defect #1).

    `AbstractPoint._canonical_scalar()` replaces a multiplier with the one odd
    number congruent to it modulo the order that lies between the order and
    three times it.  Odd is the precondition of the recoding, congruent is what
    keeps the result of the multiplication the same -- the order of a point
    times that point is the point at infinity, so adding a multiple of the
    order to a multiplier does not move the product -- and being below three
    orders, and so below ``2 ** (bit_length(order) + 2)``, is what lets the
    number of digit positions be sized from the public order alone.

    There is exactly one such value for any multiplier, and it is reached
    without a branch: the residue is odd or even, and one order is added to it
    where it is even and two where it is odd.  Every multiplier therefore costs
    the same normalisation, which is the property the tests below establish
    first.

    What normalising does **not** do is give every multiplier the same width,
    and the tests here assert the width that it does give rather than a width
    it does not.  Three orders reach one bit above the order for some curves
    and two for others, so a canonical multiplier is anywhere from
    ``bit_length(order)`` to ``bit_length(3 * order - 2)`` bits wide, and which
    of those widths a particular multiplier gets follows its residue.  A Python
    integer costs what its width costs, so a per-operation cost that varies by
    a bit or two of operand width remains; the number of *point operations* is
    what is fixed, by the number of digit positions, which is asserted in
    `TestFixedDigitRecoding`, and it is the number of point operations that
    CVE-2024-23342 was reported on.  ``SECURITY.md`` records the residue rather
    than claiming it away, and no test here asserts a constant width, because
    that claim would be false.

    One further residual is named and measured here rather than left implicit.
    A ladder adds the digit of the lowest position last, to an accumulator that
    then holds the canonical value minus that digit times the point, so the two
    operands of that last addition coincide exactly where the value is
    congruent to twice that digit modulo the order.  At most two residues of
    any order are, none at all for some -- SECP160r1 among the curves this
    library registers -- and they are named as literals, checked to be the only
    ones, and measured down to the individual coordinate formula, so that what
    they cost is a stated number rather than an unexamined difference.
    """

    CURVES = (
        NIST256p,
        SECP256k1,
        BRAINPOOLP256r1,
        BRAINPOOLP384r1,
        BRAINPOOLP512r1,
        SECP160r1,
        Ed25519,
    )

    def multipliers(self, order):
        """Multipliers spanning the edges and every width in between."""
        order = int(order)
        scalars = [0, 1, 2, 3, order - 2, order - 1, order, order + 1]
        scalars.extend([2 * order, 2 * order + 1, 3 * order - 1])
        for width in stratified_widths(order):
            scalars.extend(scalars_of_width(width, 2, seed=7))
        return scalars

    def expected_canonical(self, multiplicand, order):
        """
        The one value `_canonical_scalar()` can answer with, derived here.

        The values congruent to the multiplier modulo the order that lie
        between the order and three times it are ``residue + order`` and
        ``residue + 2 * order``; the order being odd their parities differ, so
        exactly one of them is odd.  Found here by walking those two and
        keeping the odd one, rather than by repeating the arithmetic of the
        implementation, so that a wrong multiple or a wrong interval fails
        these tests instead of being agreed with.

        :param int multiplicand: the multiplier being normalised
        :param int order: the order it is normalised against

        :return: the value the implementation has to answer with
        :rtype: int
        """
        order = int(order)
        residue = int(multiplicand) % order
        odd = [
            residue + step * order
            for step in (1, 2)
            if (residue + step * order) % 2
        ]
        self.assertEqual(len(odd), 1)
        return odd[0]

    def degenerate_residues(self, order):
        """
        Every residue whose canonical form ends a ladder on two equal operands.

        Solved from the order rather than searched for: the residue has to be
        twice a digit the recoding can produce, which leaves one candidate per
        digit to check, and whether it really is one is settled by reading the
        lowest digit of the canonical form of that candidate.

        :param int order: order of the point

        :return: the residues, ascending
        :rtype: list of int
        """
        order = int(order)
        low_bits = 1 << (ellipticcurve._MUL_WINDOW + 1)
        half = low_bits >> 1
        found = []
        for digit in range(1 - half, half, 2):
            residue = (2 * digit) % order
            canonical = self.expected_canonical(residue, order)
            if (canonical % low_bits) - half != digit:
                continue
            found.append(residue)
        return sorted(set(found))

    def widths_realised(self, order):
        """
        One canonical multiplier of every width an order can produce.

        Every odd value between the order and three times it is the canonical
        form of exactly one residue, namely of itself modulo the order, so a
        width is realised as soon as such a value of that width exists.  The
        smallest odd value at or above each power of two is taken, which is
        what makes the widths this returns the complete set rather than the
        ones some sample happened to hit.

        :param int order: order of the point

        :return: the width of each value, mapped to that value
        :rtype: dict of int to int
        """
        order = int(order)
        realised = {}
        for width in range(bit_length(order), bit_length(3 * order - 2) + 1):
            low = max(order, 1 << (width - 1))
            value = low + 1 - (low & 1)
            self.assertLess(value, 3 * order)
            self.assertEqual(bit_length(value), width)
            realised[width] = value
        return realised

    def test_every_registered_curve_has_an_odd_order(self):
        """
        The precondition of the parity correction, over all 26 curves.

        Normalising adds a multiple of the order to a multiplier to land on an
        odd number, which only works if the order is odd itself.  Every curve
        this library registers has a prime order, so it holds for all of them,
        but it is asserted rather than assumed because a
        curve is constructed from public parameters.
        """
        self.assertGreater(len(curves), 0)
        for curve in curves:
            self.assertEqual(int(curve.order) % 2, 1)

    def test_every_registered_curve_takes_the_fixed_length_ladder(self):
        """
        Every registered curve declares an order the ladder can use.

        The fixed length recoding needs an order that is known, odd and wider
        than the largest digit it emits, so a curve whose order failed any of
        those would fall back to the recoding whose cost follows the
        multiplier.  None of them does.  Reaching the ladder also needs the
        point being multiplied to carry that order, which is a property of the
        point rather than of the curve, and which a point decoded from an
        encoding does not have; `TestECDHKeyAgreement` is where that is
        asserted and where what it costs is measured.
        """
        for curve in curves:
            self.assertTrue(PointJacobi._fixed_ladder_usable(int(curve.order)))

    def test_which_orders_the_fixed_length_ladder_refuses(self):
        """
        An order has to be known, odd, and wider than the widest digit.

        Both bounds are consequences of the recoding rather than thresholds
        anyone chose.  An even order admits no odd multiplier congruent to an
        even residue, so there is no canonical value to recode; and an order no
        larger than the largest digit the recoding emits is one where the odd
        multiple that digit names is a multiple of the order, that is the point
        at infinity, which the affine entries of a multiplication table cannot
        hold.  At the one digit width this module uses the largest digit is
        fifteen, so seventeen is the narrowest order that can be used at all.
        """
        self.assertTrue(PointJacobi._fixed_ladder_usable(SMALLEST_ORDER))
        self.assertFalse(PointJacobi._fixed_ladder_usable(SMALLEST_ORDER - 2))
        self.assertFalse(PointJacobi._fixed_ladder_usable(SMALLEST_ORDER - 1))
        self.assertFalse(PointJacobi._fixed_ladder_usable(SMALLEST_ORDER + 1))
        self.assertTrue(PointJacobi._fixed_ladder_usable(SMALLEST_ORDER + 2))
        self.assertFalse(PointJacobi._fixed_ladder_usable(0))
        self.assertFalse(PointJacobi._fixed_ladder_usable(None))
        self.assertFalse(
            PointJacobi._fixed_ladder_usable(2 * int(NIST256p.order))
        )
        # seven is the order of the point on the curve of 23 points that
        # `test_ellipticcurve` and `TestEdgeCasePreservation` below both use:
        # odd, and no wider than the widest digit
        self.assertFalse(PointJacobi._fixed_ladder_usable(7))

    def test_the_width_the_orders_above_the_floor_are_recoded_with(self):
        """
        There is one digit width, and one floor below which it cannot work.

        Every odd order from `SMALLEST_ORDER` upwards is recoded with that
        width; every even order and every order below the floor is left on the
        multiplier-driven ladder rather than recoded more narrowly, since a
        narrower window would refuse fewer orders only by making the widest
        digit smaller and would refuse the same kind of order for the same
        reason.  Asserting the exact boundary orders is what makes this
        stronger than asserting that some width comes back.
        """
        preferred = ellipticcurve._MUL_WINDOW
        largest_digit = (1 << preferred) - 1

        self.assertEqual(PointJacobi._fixed_window(SMALLEST_ORDER), preferred)
        self.assertEqual(SMALLEST_ORDER, largest_digit + 2)
        self.assertEqual(PointJacobi._fixed_window(89), preferred)
        self.assertEqual(PointJacobi._fixed_window(SMALLEST_ORDER - 2), 0)
        for curve in curves:
            self.assertEqual(
                PointJacobi._fixed_window(int(curve.order)), preferred
            )
        for order in (0, None, 7, 15, 16, 18, 2 * int(NIST256p.order)):
            self.assertEqual(PointJacobi._fixed_window(order), 0)
        for order in (17, 19, 29, 31, 41, 43, 85, 87, 89):
            self.assertEqual(PointJacobi._fixed_window(order), preferred)
        # the predicate is exactly "a width was found", so the two never
        # disagree, and the width is the one width or nothing
        for order in range(0, 200):
            self.assertEqual(
                bool(PointJacobi._fixed_window(order)),
                PointJacobi._fixed_ladder_usable(order),
                order,
            )
            self.assertIn(PointJacobi._fixed_window(order), (0, preferred))
            self.assertEqual(
                bool(PointJacobi._fixed_window(order)),
                bool(order) and order % 2 == 1 and order > largest_digit,
                order,
            )

    def test_the_normalised_multiplier_is_odd_and_bounded(self):
        """Odd, and between the order and three times it."""
        for curve in self.CURVES:
            order = int(curve.order)
            for scalar in self.multipliers(order):
                canonical = canonical_scalar(scalar, order)
                self.assertEqual(canonical % 2, 1)
                self.assertGreaterEqual(canonical, order)
                self.assertLess(canonical, 3 * order)

    def test_the_normalised_multiplier_is_congruent_to_the_original(self):
        """The property that keeps the product of the multiplication put."""
        for curve in self.CURVES:
            order = int(curve.order)
            for scalar in self.multipliers(order):
                canonical = canonical_scalar(scalar, order)
                self.assertEqual(canonical % order, scalar % order)

    def test_the_normalised_multiplier_is_the_only_value_it_could_be(self):
        """
        There is one odd congruent value in the interval, and it is the answer.

        The expectation is built by walking the two congruent values the
        interval holds and keeping the odd one, which is a different expression
        of the rule from the one the implementation uses, so agreeing with it
        is evidence rather than a tautology.
        """
        for curve in self.CURVES:
            order = int(curve.order)
            for scalar in self.multipliers(order):
                self.assertEqual(
                    canonical_scalar(scalar, order),
                    self.expected_canonical(scalar, order),
                )

    def test_the_normalised_multiplier_fits_the_digit_positions(self):
        """
        Two bits wider than the order is always enough to hold it.

        This is what `_fixed_digit_count()` relies on, and it is the whole
        reason the number of digit positions can be derived from the order
        without ever looking at the multiplier.
        """
        for curve in self.CURVES:
            order = int(curve.order)
            digits, _ = fixed_ladder_shape(order)
            for scalar in self.multipliers(order):
                canonical = canonical_scalar(scalar, order)
                self.assertLess(canonical, 1 << (bit_length(order) + 2))
                self.assertLess(
                    canonical, 1 << (digits * ellipticcurve._MUL_WINDOW)
                )

    def test_the_parity_correction_adds_one_order_or_two(self):
        """
        Which multiple each parity gets, on multipliers whose residue is known.

        A residue of zero and a residue of one are the two ends of the
        correction: the first is even and gets one order, the second is odd and
        gets two.  Both are values the secret bearing entry points of this
        library accept, and both are stated here as exact values rather than as
        a property, so nothing but the correction itself can satisfy them.
        """
        for curve in self.CURVES:
            order = int(curve.order)
            self.assertEqual(canonical_scalar(0, order), order)
            self.assertEqual(canonical_scalar(order, order), order)
            self.assertEqual(canonical_scalar(2 * order, order), order)
            self.assertEqual(canonical_scalar(1, order), 1 + 2 * order)
            self.assertEqual(canonical_scalar(2, order), 2 + order)
            self.assertEqual(
                canonical_scalar(order - 1, order), order - 1 + order
            )
            self.assertEqual(
                canonical_scalar(order - 2, order), order - 2 + 2 * order
            )
            # and the multiples of the order really are answered with an odd
            # multiple of it
            self.assertEqual(canonical_scalar(0, order) % order, 0)
            self.assertEqual(canonical_scalar(0, order) % 2, 1)

    def test_the_width_of_the_normalised_multiplier_is_not_fixed(self):
        """
        The widths a canonical multiplier takes, as literals per curve.

        Normalising bounds the width by the order and does not fix it: the
        interval the answers come from starts at the order and is two orders
        wide, so it straddles at least one power of two and, where the order is
        above two thirds of its own next power of two, two of them.  The widths
        each curve below produces are carried here as literal pairs, every one
        of them is shown to be realised by a multiplier this test names, and
        every width the multipliers this class walks produce is shown to be one
        of them.

        Asserting the range rather than a single value is deliberate.  A
        constant width is not what this countermeasure provides, and a test
        that claimed one would be asserting something false; what is fixed is
        the number of point operations, which `TestFixedDigitRecoding` and the
        operation count classes above pin.  The width that remains is the
        residual ``SECURITY.md`` records.
        """
        expected = (
            (NIST256p, 256, 258),
            (SECP256k1, 256, 258),
            (BRAINPOOLP256r1, 256, 257),
            (BRAINPOOLP384r1, 384, 385),
            (BRAINPOOLP512r1, 512, 514),
            (SECP160r1, 161, 162),
            (Ed25519, 253, 254),
        )
        self.assertEqual(
            [curve for curve, _, _ in expected], list(self.CURVES)
        )

        for curve, narrowest, widest in expected:
            order = int(curve.order)
            self.assertEqual(bit_length(order), narrowest)
            self.assertEqual(bit_length(3 * order - 2), widest)

            realised = self.widths_realised(order)
            self.assertEqual(
                sorted(realised.keys()), list(range(narrowest, widest + 1))
            )
            for width, value in realised.items():
                self.assertEqual(canonical_scalar(value % order, order), value)
                self.assertEqual(bit_length(value), width)

            widths = set()
            for scalar in self.multipliers(order):
                widths.add(bit_length(canonical_scalar(scalar, order)))
            for scalar in self.degenerate_residues(order):
                widths.add(bit_length(canonical_scalar(scalar, order)))
            self.assertTrue(widths)
            for width in sorted(widths):
                self.assertGreaterEqual(width, narrowest)
                self.assertLessEqual(width, widest)

            # the two ends are reached by multipliers that need no search
            self.assertEqual(bit_length(canonical_scalar(0, order)), narrowest)
            self.assertEqual(
                bit_length(canonical_scalar(order - 2, order)), widest
            )

    def test_which_multipliers_end_a_ladder_on_two_equal_operands(self):
        """
        Named, counted, and pinned to exact values.

        Which residues have a canonical form congruent to twice their own
        lowest digit follows from the order alone, so they are stated here as
        literals: at most two per order, and none at all for SECP160r1.  The
        point of pinning them is that the tests below cannot pass by finding
        nothing to measure, and that a change to the normalisation which moved
        them would have to be noticed here rather than absorbed.
        """
        low_bits = 1 << (ellipticcurve._MUL_WINDOW + 1)
        half = low_bits >> 1
        expected = (
            (NIST256p, [int(NIST256p.order) - 6]),
            (SECP256k1, [30]),
            (BRAINPOOLP256r1, [18, int(BRAINPOOLP256r1.order) - 10]),
            (BRAINPOOLP384r1, [22]),
            (BRAINPOOLP512r1, [14, int(BRAINPOOLP512r1.order) - 22]),
            (SECP160r1, []),
            (Ed25519, [6]),
        )
        self.assertEqual([curve for curve, _ in expected], list(self.CURVES))

        for curve, degenerate in expected:
            order = int(curve.order)
            self.assertEqual(self.degenerate_residues(order), degenerate)
            self.assertLessEqual(len(degenerate), 2)
            for scalar in degenerate:
                canonical = canonical_scalar(scalar, order)
                digit = (canonical % low_bits) - half
                self.assertEqual(digit % 2, 1)
                self.assertEqual((canonical - 2 * digit) % order, 0)

    def test_only_those_multipliers_end_a_ladder_on_two_equal_operands(self):
        """
        Every residue that could break it, and only the named ones do.

        An accumulator that coincides with the point being added to it is the
        one input the addition formulas answer with a doubling formula instead.
        Checked here for every residue that could possibly reach it -- twice a
        digit, either sign -- and for the multipliers the rest of this class
        uses, against the list `degenerate_residues()` derives.

        A multiplier that is a multiple of the order meets the negation of its
        addend rather than the addend itself; that sum being the point at
        infinity is the correct answer, and it perturbs no formula choice.
        """
        low_bits = 1 << (ellipticcurve._MUL_WINDOW + 1)
        half = low_bits >> 1

        for curve in self.CURVES:
            order = int(curve.order)
            degenerate = self.degenerate_residues(order)
            residues = set(
                (2 * digit) % order for digit in range(1 - half, half, 2)
            )
            residues.update(
                scalar % order for scalar in self.multipliers(order)
            )

            for residue in sorted(residues):
                canonical = canonical_scalar(residue, order)
                digit = (canonical % low_bits) - half
                equal_operands = (canonical - 2 * digit) % order == 0
                self.assertEqual(
                    equal_operands, residue in degenerate, "%d" % residue
                )
                if not residue:
                    self.assertEqual(canonical % order, 0)
                    self.assertFalse(equal_operands)

    def assert_degenerate_ladder(self, curve, degenerate, plain, extra):
        """
        Assert what a multiplier with two equal operands actually costs.

        Down to the individual coordinate formulas, not only to the two
        dispatchers: on a short Weierstrass curve the substitution is entered
        from inside `PointJacobi._add_with_z2_1()` and answered by
        `_double_with_z_1()`, so the count of neither dispatcher moves and only
        a formula level count can see it, while on a twisted Edwards curve the
        addition dispatches back through `_double()` and the doubling count
        moves by one.  Both are asserted as exact differences, for the ladder
        of a generator and for the table-less one, since a multiplier reaches
        both.

        :param curve: the curve to multiply on
        :param int degenerate: a multiplier whose canonical form ends its
            ladder on two equal operands
        :param int plain: a multiplier of the same size that does not
        :param extra: the formula name whose count differs, and by how much
        """
        order = int(curve.order)
        self.assertIn(degenerate, self.degenerate_residues(order))
        self.assertNotIn(plain, self.degenerate_residues(order))
        point_class = point_class_of(curve)
        names = formulas_of(curve)
        extra_name, extra_count = extra
        self.assertIn(extra_name, names)

        for point in (warm_generator(curve), rebuilt_generator(curve, False)):
            affected, profile = count_formula_calls(
                point_class, names, multiplier(point, degenerate)
            )
            unaffected, plain_profile = count_formula_calls(
                point_class, names, multiplier(point, plain)
            )

            counted = dict(profile)
            plain_counted = dict(plain_profile)
            difference = []
            for name in names:
                if counted[name] != plain_counted[name]:
                    difference.append(
                        (name, counted[name] - plain_counted[name])
                    )
            self.assertEqual(difference, [(extra_name, extra_count)])
            # the two dispatchers a count of point operations sees move only
            # where the addition formula of the curve type dispatches back
            # through one of them
            for name in ("_add", "_double"):
                if name == extra_name:
                    continue
                self.assertEqual(counted[name], plain_counted[name])
            # the right point came back: adding the point once more has to give
            # what multiplying by one more does, and that multiplier is not one
            # of the degenerate ones
            self.assertEqual(affected + point, point * (degenerate + 1))
            self.assertEqual(unaffected + point, point * (plain + 1))

    def test_the_degenerate_ladder_of_secp256k1(self):
        """Weierstrass: correct, and one field level doubling more."""
        self.assert_degenerate_ladder(
            SECP256k1, 30, 32, ("_double_with_z_1", 1)
        )

    def test_the_degenerate_ladder_of_brainpoolp512r1(self):
        """The same, on a curve that has two such residues."""
        self.assert_degenerate_ladder(
            BRAINPOOLP512r1, 14, 16, ("_double_with_z_1", 1)
        )

    def test_the_degenerate_ladder_of_nist256p(self):
        """The same, where the residue sits just below the order."""
        order = int(NIST256p.order)
        self.assert_degenerate_ladder(
            NIST256p, order - 6, order - 4, ("_double_with_z_1", 1)
        )

    def test_the_degenerate_ladder_of_ed25519(self):
        """Edwards: correct, and one counted doubling more."""
        self.assert_degenerate_ladder(Ed25519, 6, 8, ("_double", 1))

    def test_no_registered_curve_leaves_secp160r1_a_degenerate_residue(self):
        """
        The residual is not universal, which is worth stating exactly.

        SECP160r1 has no residue whose canonical form ends its ladder on two
        equal operands, so on that curve the count and the formula profile of a
        multiplication are the same for every multiplier there is.  Asserted
        for the two ladders a multiplier reaches, over the residues that could
        have been degenerate on another curve.
        """
        order = int(SECP160r1.order)
        self.assertEqual(self.degenerate_residues(order), [])
        low_bits = 1 << (ellipticcurve._MUL_WINDOW + 1)
        half = low_bits >> 1
        candidates = sorted(
            set((2 * digit) % order for digit in range(1 - half, half, 2))
        )
        names = formulas_of(SECP160r1)
        for point in (
            warm_generator(SECP160r1),
            rebuilt_generator(SECP160r1, False),
        ):
            profiles = set()
            for scalar in candidates:
                _, profile = count_formula_calls(
                    PointJacobi, names, multiplier(point, scalar)
                )
                profiles.add(profile)
            self.assertEqual(len(profiles), 1)

    def assert_padding_does_not_move_the_product(self, curve, scalars):
        order = int(curve.order)
        generator = warm_generator(curve)
        table_less = rebuilt_generator(curve, generator=False)
        for scalar in scalars:
            product = generator * scalar
            self.assertEqual(product, generator * (scalar + order))
            self.assertEqual(product, generator * (scalar + 2 * order))
            self.assertEqual(
                product, generator * canonical_scalar(scalar, order)
            )
            self.assertEqual(product, table_less * scalar)
            self.assertEqual(product, table_less * (scalar + 2 * order))

    def test_padding_does_not_move_the_product_on_secp160r1(self):
        """
        Adding a multiple of the order leaves the point where it was.

        This is the identity that makes the countermeasure invisible: it is why
        `Private_key.sign()` could stop padding the nonce itself and hand it
        over untouched, and why the signatures the library produces did not
        change.  Asserted for both ladders, since a multiplication normalises
        the multiplier whether the point carries a table or not.
        """
        order = int(SECP160r1.order)
        scalars = [2, 3, order - 1]
        scalars.extend(scalars_of_width(bit_length(order), 2, seed=8))
        scalars.extend(scalars_of_width(64, 2, seed=8))
        self.assert_padding_does_not_move_the_product(SECP160r1, scalars)

    def test_padding_does_not_move_the_product_on_nist256p(self):
        order = int(NIST256p.order)
        scalars = [2, order - 1]
        scalars.extend(scalars_of_width(bit_length(order), 2, seed=9))
        scalars.extend(scalars_of_width(64, 2, seed=9))
        self.assert_padding_does_not_move_the_product(NIST256p, scalars)

    def test_padding_does_not_move_the_product_on_ed25519(self):
        order = int(Ed25519.order)
        scalars = [2, order - 1]
        scalars.extend(scalars_of_width(bit_length(order), 2, seed=10))
        scalars.extend(scalars_of_width(64, 2, seed=10))
        self.assert_padding_does_not_move_the_product(Ed25519, scalars)

    @settings(**NO_OLD_SETTINGS)
    @given(st.integers(min_value=0, max_value=int(NIST256p.order) * 5))
    def test_normalising_an_arbitrary_multiplier(self, multiplicand):
        """Every property above, over multipliers Hypothesis picks."""
        order = int(NIST256p.order)
        canonical = canonical_scalar(multiplicand, order)

        self.assertEqual(canonical % 2, 1)
        self.assertGreaterEqual(canonical, order)
        self.assertLess(canonical, 3 * order)
        self.assertEqual(canonical % order, multiplicand % order)
        self.assertEqual(
            canonical, self.expected_canonical(multiplicand, order)
        )
        self.assertGreaterEqual(bit_length(canonical), bit_length(order))
        self.assertLessEqual(bit_length(canonical), bit_length(3 * order - 2))

    @settings(**POINT_SETTINGS)
    @given(st.integers(min_value=0, max_value=int(SECP160r1.order) - 1))
    def test_multiplying_by_an_arbitrary_normalised_multiplier(
        self, multiplicand
    ):
        """The point identity, over multipliers Hypothesis picks."""
        order = int(SECP160r1.order)
        generator = warm_generator(SECP160r1)
        product = generator * multiplicand

        self.assertEqual(product, generator * (multiplicand + order))
        self.assertEqual(product, generator * (multiplicand + 2 * order))
        self.assertEqual(
            product, generator * canonical_scalar(multiplicand, order)
        )


class TestNonceUnpaddingRegression(unittest.TestCase):
    """
    The padding a lower layer used to undo (Defect #1).

    Releases up to 0.19.1 hid the width of the nonce in
    `ecdsa.ecdsa.Private_key.sign()`: they added the order to it, and the order
    once more if that had not made it wider, so that the value handed to the
    multiplication always had one bit more than the order.  The multiplication
    then reduced whatever it was given modulo twice the order.  The first of
    those two paddings survived that -- the nonce plus one order is below twice
    the order -- and the second did not, because the nonce plus two orders lies
    between two and three times the order and so came back out as the bare
    nonce.  The countermeasure was therefore cancelled exactly in the branch it
    had been written for.

    This is the failure the side channel analysis of Mozilla's NSS
    (arXiv:2008.06004) named nonce unpadding, where a padding applied by a high
    level routine is stripped by a lower level one.  The fix is not to change
    the modulus: the padding is gone from `Private_key.sign()` altogether and
    the arithmetic layer normalises the multiplier itself, so there is no
    longer a padding for a reduction to undo.

    Everything here is about the ECDSA signing path and only about it, because
    `ecdsa.ecdsa.Private_key.sign()` is the one place that padding was ever
    applied.  The Edwards curves reached the same reduction without ever having
    been padded, which is a leak of its own rather than a cancelled
    countermeasure; `TestEdwardsRawScalarRegression` is where that one is
    stated.
    """

    #: The registered short Weierstrass curve whose order left the old padding
    #: without effect for all but a vanishing fraction of the nonces.  Its
    #: order is barely above a power of two, so almost the whole range below it
    #: took the branch the reduction undid.
    ALWAYS_CANCELLED = (SECP160r1,)
    OFTEN_CANCELLED = (
        BRAINPOOLP256r1,
        BRAINPOOLP384r1,
        BRAINPOOLP512r1,
    )

    def cancelled_nonces(self, curve, width, count):
        """
        Nonces of `width` bits, below the order, whose padding was cancelled.

        Both conditions are needed for these to be the values the defect
        actually mishandled: a nonce is reduced modulo the order before it is
        padded, and only the nonces below the difference between the order and
        the next power of two took the branch that the reduction undid.
        """
        order = int(curve.order)
        nonces = []
        for scalar in scalars_of_width(width, count * 32, seed=11):
            if scalar >= order:
                continue
            if not old_padding_was_cancelled(scalar, order):
                continue
            nonces.append(scalar)
            if len(nonces) == count:
                break
        self.assertEqual(len(nonces), count)
        return nonces

    def widest_nonce_width(self, curve):
        """
        Widest bit length this test uses for a nonce of `curve`.

        One below the width of the order rather than equal to it: a nonce is
        smaller than the order, and on a curve whose order is barely above a
        power of two -- SECP160r1 is one -- almost no nonce reaches the
        width of
        the order at all.
        """
        return bit_length(int(curve.order)) - 1

    def test_the_old_reduction_gave_the_bare_nonce_back(self):
        """
        The arithmetic of the cancellation, stated on its own.

        Nothing about the current code is exercised here.  This is the identity
        that made the old countermeasure useless, kept as a statement of what
        the tests below are guarding against: the nonce plus two orders,
        reduced modulo twice the order, is the nonce.
        """
        for curve in self.ALWAYS_CANCELLED + self.OFTEN_CANCELLED:
            order = int(curve.order)
            width = self.widest_nonce_width(curve)
            for nonce in self.cancelled_nonces(curve, width, 2):
                padded = nonce + 2 * order
                self.assertEqual(padded % (2 * order), nonce)
                self.assertEqual(bit_length(nonce), width)
                # the other branch, the one that did survive, is what makes
                # this a cancellation of half the countermeasure rather than of
                # all of it
                self.assertEqual((nonce + order) % (2 * order), nonce + order)

    def test_a_narrow_nonce_was_cancelled_on_every_curve(self):
        """
        The nonces an attack selects for were the unprotected ones everywhere.

        A curve whose order sits just below a power of two -- P-256 is one --
        cancelled the padding for a negligible fraction of uniformly drawn
        nonces, which is what made it look unaffected.  It was not: the
        cancelled range covers every nonce narrower than the difference between
        the order and that power of two, and a narrow nonce is exactly what a
        timing attack keeps.
        """
        for curve in (
            self.ALWAYS_CANCELLED + self.OFTEN_CANCELLED + CURVES_256_BIT
        ):
            order = int(curve.order)
            room = (1 << bit_length(order)) - order
            self.assertGreater(room, 1 << 64)
            for nonce in scalars_of_width(64, 2, seed=12):
                self.assertTrue(old_padding_was_cancelled(nonce, order))

    def test_how_much_of_the_range_the_old_padding_left_unprotected(self):
        """
        How many nonces the cancellation covered, per curve, exactly.

        Stated as integer comparisons rather than as a probability: a floating
        point ratio of numbers this size rounds, and for the worst curve here it
        rounds to exactly one, which would read as a claim that the
        cancellation was total when in truth a vanishing fraction of nonces
        escaped it.  On SECP160r1 more than 999 nonces in every 1000 were
        cancelled; on the three Brainpool curves more than 490 in
        every 1000, the widest of them being the worst at over 810; and on
        P-256 and SECP256k1 fewer than one in ten thousand, which is why they
        looked unaffected under a uniformly drawn nonce.
        """
        for curve in self.ALWAYS_CANCELLED:
            order = int(curve.order)
            room = (1 << bit_length(order)) - order
            self.assertGreater(room * 1000, 999 * order)
            self.assertLess(room, order)

        for curve in self.OFTEN_CANCELLED:
            order = int(curve.order)
            room = (1 << bit_length(order)) - order
            self.assertGreater(room * 1000, 490 * order)
            self.assertLess(room * 1000, 999 * order)

        order = int(BRAINPOOLP384r1.order)
        room = (1 << bit_length(order)) - order
        self.assertGreater(room * 1000, 810 * order)

        for curve in (NIST256p, SECP256k1):
            order = int(curve.order)
            room = (1 << bit_length(order)) - order
            self.assertLess(room * 10000, order)

    def test_the_share_of_the_range_the_old_padding_left_unprotected(self):
        """
        The same count as a probability, to the last bit of a float.

        The integer comparisons above are the accurate statement, and this is
        the number a reader reaches for: the chance that a uniformly drawn
        nonce took the cancelled branch, which is the room between the order
        and the next power of two divided by the order.  On SECP160r1 it rounds
        to exactly one, meaning the countermeasure did next to nothing there;
        the value is pinned here so that a
        change to the curve table or to this arithmetic cannot quietly move
        it.  The rounding is why the test above states the same facts as
        integers as well.
        """
        expected = (
            (SECP160r1, 1.0),
            (BRAINPOOLP256r1, 0.5060435053035426),
            (BRAINPOOLP384r1, 0.8191751058744173),
            (BRAINPOOLP512r1, 0.49825282740389876),
        )
        for curve, share in expected:
            order = int(curve.order)
            room = (1 << bit_length(order)) - order
            self.assertEqual(room / float(order), share)

    def test_normalising_keeps_the_padding_the_reduction_used_to_undo(self):
        """
        The nonces that used to lose their padding keep it now.

        Two things have to hold at once.  The value the ladder is driven with is
        no longer the bare nonce but one bounded by the order alone -- at least
        as wide as the order and at most two bits wider, which is the range
        `TestCanonicalScalar` pins -- so the number of digits it is recoded into
        is a function of the order, and with it the number of point operations
        those digits cost; and it is still congruent to the nonce modulo the
        order, so the point -- and with it the signature -- is unchanged.

        The width itself is not one value, and this test does not claim it is:
        what the old padding was reaching for was a width that did not follow
        the nonce, and a width bounded by the order is that, while the count of
        point operations -- which is what the advisory reported -- is fixed
        outright.  The number of digits is asserted here for every one of these
        nonces, which is the statement that carries the countermeasure.
        """
        for curve in self.ALWAYS_CANCELLED + self.OFTEN_CANCELLED:
            order = int(curve.order)
            width = self.widest_nonce_width(curve)
            digits, _ = fixed_ladder_shape(order)
            nonces = self.cancelled_nonces(curve, width, 2)
            nonces.extend(scalars_of_width(64, 2, seed=13))
            for nonce in nonces:
                canonical = canonical_scalar(nonce, order)
                self.assertGreaterEqual(canonical, order)
                self.assertNotEqual(canonical, nonce)
                self.assertEqual(canonical % order, nonce)
                self.assertGreater(bit_length(canonical), bit_length(nonce))
                self.assertGreaterEqual(
                    bit_length(canonical), bit_length(order)
                )
                self.assertLessEqual(
                    bit_length(canonical), bit_length(order) + 2
                )
                self.assertEqual(
                    len(
                        PointJacobi._fixed_digits(
                            canonical, digits, ellipticcurve._MUL_WINDOW
                        )
                    ),
                    digits,
                )

    def assert_a_narrow_and_a_wide_nonce_cost_the_same(self, curve):
        """
        The heart of this class: one addition count for both ends.

        The wide nonce is one the old code would have stripped the padding
        from and the narrow one is a quarter of the width of the order.  Before
        the countermeasure the two differed by tens of point additions, which
        is the whole signal a Minerva attack accumulates.
        """
        generator = warm_generator(curve)
        point_class = point_class_of(curve)
        digits, _ = fixed_ladder_shape(curve.order)
        wide = self.cancelled_nonces(curve, self.widest_nonce_width(curve), 2)
        narrow = scalars_of_width(64, 2, seed=14)

        counts = set()
        for nonce in wide + narrow:
            _, additions, doublings = count_point_operations(
                point_class, multiplier(generator, nonce)
            )
            counts.add(additions)
            self.assertEqual(doublings, 0)

        self.assertEqual(sorted(counts), [digits])

    def test_a_narrow_and_a_wide_nonce_cost_the_same_on_secp160r1(self):
        """SECP160r1, where the old padding was cancelled almost always."""
        self.assert_a_narrow_and_a_wide_nonce_cost_the_same(SECP160r1)

    def test_a_narrow_and_a_wide_nonce_cost_the_same_on_brainpoolp256r1(self):
        self.assert_a_narrow_and_a_wide_nonce_cost_the_same(BRAINPOOLP256r1)

    def test_a_narrow_and_a_wide_nonce_cost_the_same_on_brainpoolp384r1(self):
        self.assert_a_narrow_and_a_wide_nonce_cost_the_same(BRAINPOOLP384r1)

    def test_a_narrow_and_a_wide_nonce_cost_the_same_on_brainpoolp512r1(self):
        self.assert_a_narrow_and_a_wide_nonce_cost_the_same(BRAINPOOLP512r1)

    def test_the_signing_path_no_longer_pads_the_nonce_itself(self):
        """
        What the signing path hands the multiplication is the bare nonce.

        The padding `Private_key.sign()` used to apply is gone, so the
        multiplier the multiplication receives is the nonce reduced modulo the
        order and nothing else -- not the nonce plus one order, which is what
        releases up to 0.19.1 handed over, and not plus two, which is what they
        handed over for the nonces the reduction then cancelled it for.  What
        makes removing the padding safe is that it never mattered: signing with
        the nonce, or with either padded form of it, produces one and the same
        signature, because all three multiply the generator to the same point.
        """
        curve = SECP160r1
        order = int(curve.order)
        secret = 0x2A3B4C5D6E7F8091A2B3C4D5E6F708192A3B4C5D % order
        generator = curve.generator
        private_key = Private_key(
            Public_key(generator, generator * secret), secret
        )
        digest = 0x1F2E3D4C5B6A798877665544332211FF % order

        for nonce in self.cancelled_nonces(
            curve, self.widest_nonce_width(curve), 1
        ) + scalars_of_width(64, 1, seed=15):
            reference = private_key.sign(digest, nonce)
            for padded in (nonce, nonce + order, nonce + 2 * order):
                signature, multipliers = captured_multipliers(
                    PointJacobi,
                    lambda value=padded: private_key.sign(digest, value),
                )
                self.assertEqual(multipliers, [nonce % order])
                self.assertEqual(
                    (signature.r, signature.s), (reference.r, reference.s)
                )
            self.assertEqual(reference.r, (generator * nonce).x() % order)


class TestEdwardsRawScalarRegression(unittest.TestCase):
    """
    What the Edwards ladder was handed, and what that used to cost.

    The padding the class above is about was applied in one place and one place
    only, `ecdsa.ecdsa.Private_key.sign()`, and EdDSA never went through it:
    `ecdsa.eddsa.PrivateKey.sign()` hashes and multiplies the generator by the
    whole hash -- 64 bytes of it on Ed25519, 114 on Ed448 -- so there was no
    padding here for a reduction to cancel.  What there was is plainer than a
    cancelled countermeasure.  Releases up to 0.19.1 reduced that hash modulo
    twice the order and then drove a ladder whose length was the width of what
    came out and whose additions were the non zero digits of its non adjacent
    form, so the cost followed the hash.  The secret is the same secret: the
    signature carries `S = r + H(R, A, M) * s`, which gives up the private
    scalar to anyone who recovers `r`.

    The Minerva authors withdrew their EdDSA claims on the grounds that an
    implementation which does not reduce the hash modulo the curve order --
    which the protocol does not ask it to -- leaks nothing that looks
    exploitable.  That does not cleanly cover this one, which did reduce it,
    modulo twice the order rather than the order: enough to bound the value,
    not enough to leave its width alone.  Hardening the Edwards ladder is
    therefore defence in depth against the advisory rather than the letter of
    it, and is asserted here as such.

    The countermeasure treats this ladder as it treats the others: the
    multiplier is normalised to a value bounded by the order rather than by the
    hash and recoded into a fixed length sequence of digits none of which is
    zero, so a hash of any width is answered with the same number of point
    operations.
    """

    #: The two Edwards curves and how wide a value each hands its ladder: the
    #: hash function of the curve produces that many bits and the whole of it is
    #: the multiplier.  Ed25519 hashes with SHA-512 and Ed448 with SHAKE256 at
    #: 114 bytes.
    HASH_WIDTHS = ((Ed25519, 512), (Ed448, 912))

    #: The private key of the first Ed25519 test vector of RFC 8032, so that the
    #: multipliers asserted below are values any reader can reproduce.
    RFC_8032_ED25519_KEY = (
        "9d61b19deffd5a60ba844af492ec2cc4" "4449c5697b326919703bac031cae7f60"
    )

    def naf_weight(self, value):
        """Additions the ladder up to 0.19.1 would have spent on `value`."""
        return sum(1 for digit in PointJacobi._naf(value) if digit)

    def test_eddsa_signing_multiplies_by_a_whole_hash(self):
        """
        The multiplier EdDSA hands the ladder is the hash, unreduced.

        Nothing about the countermeasure is exercised here: this is what
        `ecdsa.eddsa.PrivateKey.sign()` did before it and does now, and is why
        the ladder had a raw hash to work with at all.  The public key is
        derived before the measurement, that being a multiplication of its own
        which a key performs once.
        """
        order = int(Ed25519.order)
        private = EdDSAPrivateKey(
            Ed25519.generator, a2b_hex(self.RFC_8032_ED25519_KEY)
        )
        private.public_key()

        for message, width in ((b"", 510), (b"minerva", 512)):
            _, multipliers = captured_multipliers(
                PointEdwards, lambda data=message: private.sign(data)
            )
            self.assertEqual(len(multipliers), 1)
            handed = multipliers[0]
            self.assertEqual(bit_length(handed), width)
            # wider than twice the order, so the old reduction really did have
            # something to take off, and wider than the width the normalisation
            # settles every multiplier at
            self.assertGreater(bit_length(handed), bit_length(2 * order))
            self.assertGreaterEqual(handed, 2 * order)

    def assert_the_old_reduction_left_a_spread(
        self, curve, hash_width, widths, weights
    ):
        """
        The reduction bounded a hash without fixing what it cost.

        :param curve: the Edwards curve to state this for
        :param int hash_width: bit width of the values to reduce, the width of
            the hash that curve hands its ladder
        :param widths: every distinct bit length the reduction left, ascending
        :param weights: every distinct count of non zero digits the non
            adjacent form of a reduced value has, ascending
        """
        order = int(curve.order)
        reduced = [
            value % (2 * order)
            for value in scalars_of_width(hash_width, 16, seed=71)
        ]
        for value in reduced:
            self.assertLess(value, 2 * order)
            self.assertLessEqual(bit_length(value), bit_length(2 * order))
        self.assertEqual(
            sorted(set(bit_length(value) for value in reduced)), widths
        )
        self.assertEqual(
            sorted(set(self.naf_weight(value) for value in reduced)), weights
        )

    def test_the_old_reduction_left_the_width_of_the_hash_behind(self):
        """
        The arithmetic of the Edwards leak, stated on its own.

        Nothing about the current code is exercised here.  Reducing a hash
        modulo twice the order bounds it, and bounding it is all it does: over
        sixteen values of the width each curve hashes to, the width of what came
        out took five distinct values on Ed25519 and four on Ed448, and the
        number of additions the old ladder would have spent on them -- the non
        zero digits of their non adjacent form -- took eleven and twelve.  Both
        are pinned exactly so that neither can drift without this failing, and
        both hold on a tree without the countermeasure, so this describes the
        defect rather than the code that replaced it.
        """
        self.assert_the_old_reduction_left_a_spread(
            Ed25519,
            512,
            [249, 250, 251, 252, 253],
            [79, 80, 82, 83, 84, 85, 86, 87, 88, 90, 91],
        )
        self.assert_the_old_reduction_left_a_spread(
            Ed448,
            912,
            [444, 445, 446, 447],
            [138, 139, 144, 145, 147, 150, 152, 154, 155, 156, 157, 159],
        )

    def test_a_narrow_and_a_wide_scalar_cost_the_same_on_ed25519(self):
        """
        The heart of this class: one addition count for every hash.

        The widest multiplier here is as wide as the hash EdDSA actually hands
        over and the narrowest is a quarter of the width of the order, with the
        width of the order itself and half of it in between; the old ladder
        charged the two ends tens of additions apart.  Driven through
        `PointEdwards` rather than through a signing key, since
        `SigningKey.sign_digest()` refuses an Edwards curve.
        """
        generator = warm_generator(Ed25519)
        digits, _ = fixed_ladder_shape(Ed25519.order)
        self.assertEqual(digits, 64)

        counts = set()
        for width in (512, 253, 128, 64):
            for scalar in scalars_of_width(width, 2, seed=16):
                _, additions, doublings = count_point_operations(
                    PointEdwards, multiplier(generator, scalar)
                )
                counts.add(additions)
                self.assertEqual(doublings, 0)

        self.assertEqual(sorted(counts), [digits])

    def test_the_normalised_multiplier_of_an_edwards_hash_is_bounded(self):
        """
        What replaced the reduction leaves one digit count, not one width.

        The counterpart of the reduction above.  The same values, normalised
        rather than reduced, come out odd, still congruent to the hash modulo
        the order -- so the point EdDSA commits to is the point it always was --
        and bounded by the order rather than by the hash: at least as wide as
        the order and at most two bits wider, whatever the five hundred and
        twelve bits the hash arrives with looked like.

        What is one value is the number of digits the recoding produces from
        them, and with it the number of point additions the ladder spends, which
        is what the test above measures.  A single *width* is not claimed
        because it would be false: three orders reach one bit above the order on
        Ed25519 and two on Ed448, and which of those a particular hash gets
        follows its residue.  ``SECURITY.md`` records that residue.
        """
        for curve, hash_width in self.HASH_WIDTHS:
            order = int(curve.order)
            digits, _ = fixed_ladder_shape(order)
            widths = set()
            counts = set()
            for value in scalars_of_width(hash_width, 16, seed=71):
                canonical = canonical_scalar(value, order)
                self.assertEqual(canonical % order, value % order)
                self.assertEqual(canonical % 2, 1)
                self.assertGreaterEqual(canonical, order)
                self.assertLess(canonical, 3 * order)
                widths.add(bit_length(canonical))
                counts.add(
                    len(
                        PointJacobi._fixed_digits(
                            canonical, digits, ellipticcurve._MUL_WINDOW
                        )
                    )
                )
            self.assertEqual(sorted(counts), [digits])
            for width in sorted(widths):
                self.assertGreaterEqual(width, bit_length(order))
                self.assertLessEqual(width, bit_length(3 * order - 2))

        # the widths of the two curves, as literals: one bit above the order on
        # Ed25519 and two on Ed448, and neither of them the width of the hash
        self.assertEqual(bit_length(int(Ed25519.order)), 253)
        self.assertEqual(bit_length(3 * int(Ed25519.order) - 2), 254)
        self.assertEqual(bit_length(int(Ed448.order)), 446)
        self.assertEqual(bit_length(3 * int(Ed448.order) - 2), 448)
        self.assertEqual(fixed_ladder_shape(Ed25519.order)[0], 64)
        self.assertEqual(fixed_ladder_shape(Ed448.order)[0], 112)


class TestSignatureTransparency(unittest.TestCase):
    """
    The countermeasure must not be visible from outside the library.

    Everything asserted here held before the countermeasure as well; that is
    the point of it.  No public callable gained, lost or reordered a parameter,
    no return type changed, and no signature changed value -- which is what
    made it possible to remove the padding from `Private_key.sign()` rather
    than repair it, because adding a multiple of the order to a nonce leaves
    the point, and so `r` and `s`, exactly where they were.

    The signatures below were captured by running the unmodified
    0.19.1+2.g55aca78 tree before the countermeasure existed and are asserted
    as literals.  Regenerating them from the patched code would make the
    assertion circular and prove nothing.
    """

    # a fixed private scalar, smaller than the order of both curves used here;
    # nothing about it is secret and no key material is derived from it beyond
    # these tests
    SECRET_EXPONENT = int(
        "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef", 16
    )
    DIGEST = hashlib.sha256(b"Minerva regression vector").digest()

    NIST256P_DETERMINISTIC = (
        int(
            "035c5124bd60bb403343d873460d90fb"
            "5897600f5c9eda7904e13e8bca0d7aab",
            16,
        ),
        int(
            "ccbcedea0827d333c90c56641e295798"
            "c0c773e2a8e579dd86ca683a0d78b56b",
            16,
        ),
    )
    SECP256K1_DETERMINISTIC = (
        int(
            "17b7e1f2fb3201407462c4f8df03c0cb"
            "0b26378e35159a36bee82296f23235a1",
            16,
        ),
        int(
            "02d3a5c02a350c09540319b6fbd4223b"
            "e7ce1a43b6a99581f3b3e36ab64544d3",
            16,
        ),
    )

    EXPLICIT_NONCE = int(
        "0f0e0d0c0b0a09080706050403020100fedcba9876543210", 16
    )
    NIST256P_EXPLICIT_NONCE = (
        int(
            "9320d90c2b390be00d522496818d2c40"
            "e99decd2572907734139d6be96bf0153",
            16,
        ),
        int(
            "4ec4632183978588d3fe8c1b38eda001"
            "5f0a4da2ee315182d7b30e1dbc7b5167",
            16,
        ),
    )

    def secret_for(self, curve):
        """
        The fixed private scalar, brought inside the order of `curve`.

        The two curves the captured signatures belong to both have an order
        wider than the scalar, so the reduction leaves it alone there and the
        literals stay meaningful; the narrower curves used for the properties
        that do not depend on a captured value need it.
        """
        return self.SECRET_EXPONENT % int(curve.order)

    def signing_key(self, curve):
        """A signing key over `curve` for the fixed private scalar above."""
        return SigningKey.from_secret_exponent(
            self.secret_for(curve), curve, hashlib.sha256
        )

    def entropy(self, requested):
        """
        A stand-in for `os.urandom` that always returns the same bytes.

        `randrange()` reads its randomness a byte string at a time, so a source
        that hands back a constant is enough to make a nonce it draws
        reproducible -- which is what the keyword argument exists for.
        """
        return b"\x5b" * requested

    def test_a_deterministic_signature_is_the_same_every_time(self):
        """
        Two calls with the same inputs return the same bytes.

        The nonce is derived from the key and the digest, so this held before;
        what makes it worth asserting now is the blinding the inversion of the
        nonce gained, which multiplies that nonce by a factor of its own.  If
        that factor did not cancel out algebraically, two signatures over the
        same digest with the same key would differ.
        """
        for curve in (NIST256p, SECP256k1, BRAINPOOLP256r1, SECP160r1):
            key = self.signing_key(curve)
            first = key.sign_digest_deterministic(
                self.DIGEST, hashlib.sha256, allow_truncate=True
            )
            second = key.sign_digest_deterministic(
                self.DIGEST, hashlib.sha256, allow_truncate=True
            )

            self.assertEqual(first, second)
            self.assertTrue(
                key.get_verifying_key().verify_digest(
                    first, self.DIGEST, allow_truncate=True
                )
            )

    def test_a_deterministic_signature_is_the_one_the_old_tree_produced(self):
        """The captured bytes, on the curve the advisory names and on
        one more."""
        expected = (
            (NIST256p, self.NIST256P_DETERMINISTIC),
            (SECP256k1, self.SECP256K1_DETERMINISTIC),
        )
        for curve, (r, s) in expected:
            key = self.signing_key(curve)
            signature = key.sign_digest_deterministic(
                self.DIGEST, hashlib.sha256
            )
            self.assertEqual(
                sigdecode_string(signature, int(curve.order)), (r, s)
            )

    def test_signing_twice_with_the_same_nonce_gives_the_same_signature(self):
        """
        The sharpest test of the blinding of the modular inversion.

        `Private_key.sign()` now inverts the nonce multiplied by a factor of
        its own and cancels that factor out again, so that the number of
        iterations of the extended Euclid loop two of the four inversion
        implementations run follows the factor rather than the nonce.
        Two signatures over the same digest with the same explicit nonce
        therefore have to come out byte for byte identical -- and would not, if
        the factor did not cancel exactly.
        """
        for curve in (NIST256p, SECP256k1, SECP160r1):
            key = self.signing_key(curve)
            nonce = self.EXPLICIT_NONCE % int(curve.order)
            signatures = set()
            for _ in range(4):
                signatures.add(
                    key.sign_digest(self.DIGEST, k=nonce, allow_truncate=True)
                )
            self.assertEqual(len(signatures), 1)

    def test_a_signature_with_an_explicit_nonce_matches_the_old_tree(self):
        """The captured bytes for a nonce handed in by the caller."""
        key = self.signing_key(NIST256p)
        signature = key.sign_digest(self.DIGEST, k=self.EXPLICIT_NONCE)

        self.assertEqual(
            sigdecode_string(signature, int(NIST256p.order)),
            self.NIST256P_EXPLICIT_NONCE,
        )

    def test_the_nonce_can_still_be_recovered_from_the_signature(self):
        """
        The relation a Minerva attack uses to extract the nonce it timed.

        Recovering the nonce from the signature and the private key is what
        turns a timing measurement into a lattice problem, and it is also the
        strongest statement that the signature really was produced with the
        nonce that was handed in: the countermeasure changed which value the
        ladder was driven with, not which nonce the signature belongs to.
        """
        order = int(NIST256p.order)
        secret = self.secret_for(NIST256p)
        key = self.signing_key(NIST256p)
        message = int("1f2e3d4c5b6a79881f2e3d4c5b6a7988", 16)

        nonces = [1, 2, order - 1, self.EXPLICIT_NONCE % order]
        nonces.extend(scalars_of_width(64, 2, seed=18))
        nonces.extend(scalars_of_width(256, 2, seed=19))
        for nonce in nonces:
            if not 1 <= nonce < order:
                continue
            r, s = key.sign_number(message, k=nonce)
            recovered = inverse_mod(s, order) * (message + secret * r) % order
            self.assertEqual(recovered, nonce)

    def test_the_blinding_of_the_inversion_cancels_exactly(self):
        """
        The algebra the blinded inversion rests on, on its own.

        The inverse of a blinded nonce times the blinding factor is the inverse
        of the nonce, for every factor invertible modulo the order; and every
        inversion this library can be built on maps zero to zero, so the
        blinded form is zero on exactly the inputs the bare one was and the
        check for a zero `s` that would leak the key still fires.
        """
        order = int(NIST256p.order)
        nonces = [1, 2, order - 1, self.EXPLICIT_NONCE]
        nonces.extend(scalars_of_width(64, 2, seed=16))
        factors = [1, 2, order - 1]
        factors.extend(scalars_of_width(128, 2, seed=17))
        for nonce in nonces:
            bare = inverse_mod(nonce, order)
            for factor in factors:
                blinded = (
                    inverse_mod(factor * nonce % order, order) * factor % order
                )
                self.assertEqual(blinded, bare)
        self.assertEqual(inverse_mod(0, order), 0)
        self.assertEqual(inverse_mod(7 * 0 % order, order) * 7 % order, 0)

    def test_r_is_the_same_for_a_nonce_and_for_its_padded_forms(self):
        """
        The `r` of a signature comes from the point, which padding cannot move.

        Asserted against the point arithmetic directly rather than only against
        another signature, so that the identity behind the whole change is
        visible: the first coordinate of the generator times the nonce, times
        the nonce plus one order, and times the nonce plus two orders, are one
        and the same number.
        """
        for curve in (NIST256p, SECP160r1):
            order = int(curve.order)
            key = self.signing_key(curve)
            nonce = self.EXPLICIT_NONCE % order
            signature = key.sign_digest(
                self.DIGEST, k=nonce, allow_truncate=True
            )
            r = sigdecode_string(signature, order)[0]
            generator = curve.generator

            self.assertEqual(r, (generator * nonce).x() % order)
            self.assertEqual(r, (generator * (nonce + order)).x() % order)
            self.assertEqual(r, (generator * (nonce + 2 * order)).x() % order)

    def test_every_documented_keyword_of_the_signing_api_still_works(self):
        """
        The public contract, exercised rather than introspected.

        Calling each entry point with every keyword argument it documents, and
        verifying what comes back, states that the contract is intact without
        depending on an introspection helper -- `inspect.getargspec()` is gone
        from recent Python and its replacement was never in the oldest release
        this library supports.
        """
        curve = NIST256p
        order = int(curve.order)
        key = self.signing_key(curve)
        verifier = key.get_verifying_key()
        nonce = self.EXPLICIT_NONCE % order
        data = b"a message to be hashed and signed"

        raw = key.sign_digest(
            self.DIGEST,
            entropy=self.entropy,
            sigencode=sigencode_der,
            k=nonce,
            allow_truncate=True,
        )
        self.assertTrue(
            verifier.verify_digest(
                raw,
                self.DIGEST,
                sigdecode=sigdecode_der,
                allow_truncate=True,
            )
        )

        numbers = key.sign_number(
            int("1f2e3d4c5b6a7988", 16), entropy=self.entropy, k=nonce
        )
        self.assertEqual(len(numbers), 2)
        for number in numbers:
            self.assertGreater(number, 0)
            self.assertLess(number, order)

        over_data = key.sign(
            data,
            entropy=self.entropy,
            hashfunc=hashlib.sha256,
            sigencode=sigencode_der,
            k=nonce,
            allow_truncate=True,
        )
        self.assertTrue(
            verifier.verify(
                over_data,
                data,
                hashfunc=hashlib.sha256,
                sigdecode=sigdecode_der,
                allow_truncate=True,
            )
        )

        deterministic = key.sign_digest_deterministic(
            self.DIGEST,
            hashfunc=hashlib.sha256,
            sigencode=sigencode_der,
            extra_entropy=b"\x2a",
            allow_truncate=True,
        )
        self.assertTrue(
            verifier.verify_digest(
                deterministic,
                self.DIGEST,
                sigdecode=sigdecode_der,
                allow_truncate=True,
            )
        )

        over_data_deterministic = key.sign_deterministic(
            data,
            hashfunc=hashlib.sha256,
            sigencode=sigencode_der,
            extra_entropy=b"\x2a",
        )
        self.assertTrue(
            verifier.verify(
                over_data_deterministic,
                data,
                hashfunc=hashlib.sha256,
                sigdecode=sigdecode_der,
            )
        )

    def test_the_entropy_keyword_still_selects_the_nonce(self):
        """
        A caller-supplied entropy source still decides the nonce it draws.

        The `entropy=` argument feeds nonce generation and nothing else, and the
        factor blinding the inversion is drawn from a source of the library's
        own and cancels exactly, so a caller that fixes the source a signature
        is drawn from still fixes the whole signature: two signatures drawn from
        the same fixed source are the same signature, exactly as they were
        before the countermeasure.  That the blinding factor differs between
        those two signatures all the same is asserted by `TestBlindedInversion`;
        what is asserted here is the result a caller sees.
        """
        key = self.signing_key(NIST256p)
        first = key.sign_digest(self.DIGEST, entropy=self.entropy)
        second = key.sign_digest(self.DIGEST, entropy=self.entropy)

        self.assertEqual(first, second)
        self.assertTrue(
            key.get_verifying_key().verify_digest(first, self.DIGEST)
        )

    def test_a_signature_whose_s_would_be_zero_is_still_refused(self):
        """
        The guard that refuses a signature leaking the key still fires.

        A zero `s` would disclose the private key, so `Private_key.sign()`
        refuses it.  The value it tests is now the product of a blinded inverse
        and its blinding factor, and it is only because every one of the four
        modular inversions this library can be built on maps zero to zero, and
        because the blinding cancels exactly, that the product is zero on
        exactly the inputs the bare inverse was.  A message digest congruent to
        the negation of the private key times `r` makes `s` zero for a known
        nonce, which reaches the guard without needing an unlucky draw: the
        same construction raises the same error on the unmodified tree.
        """
        curve = NIST256p
        order = int(curve.order)
        generator = curve.generator
        secret = self.secret_for(curve)
        private_key = Private_key(
            Public_key(generator, generator * secret), secret
        )
        nonce = self.EXPLICIT_NONCE % order
        r = (generator * nonce).x() % order
        # s == sinv * (message + secret * r) % n, so a message congruent to
        # -secret * r makes the second factor, and with it s, zero
        message = (order - secret * r % order) % order

        self.assertRaises(RSZeroError, private_key.sign, message, nonce)
        # the guard is reached through the blinding, and a caller that retries
        # after it fires gets the same factor again, so it has to keep firing
        for _ in range(4):
            self.assertRaises(RSZeroError, private_key.sign, message, nonce)
        self.assertNotEqual(private_key.sign(message + 1, nonce).s, 0)

    def test_a_nonce_that_reduces_to_zero_raises_what_it_always_did(self):
        """
        The degenerate nonces behave exactly as they did before.

        A nonce of zero, or one congruent to zero modulo the order, multiplies
        the generator to the point at infinity, whose first coordinate is
        `None`; taking that modulo the order raises a `TypeError`, and it did
        so before the countermeasure too.  It is asserted here rather than
        improved because the improvement would be a behaviour change, and
        `SigningKey.sign_number()` refuses such a nonce well before this point
        is reached.
        """
        curve = NIST256p
        order = int(curve.order)
        generator = curve.generator
        secret = self.secret_for(curve)
        private_key = Private_key(
            Public_key(generator, generator * secret), secret
        )

        for nonce in (0, order, 2 * order):
            self.assertRaises(TypeError, private_key.sign, 12345, nonce)

        key = self.signing_key(curve)
        self.assertRaises(
            AssertionError, key.sign_digest, self.DIGEST, None, k=0
        )


class TestBlindedInversion(unittest.TestCase):
    """
    The blinding the inversion of the nonce gained, on its own.

    Signing has to invert the nonce modulo the order of the generator, and two
    of the four inversions this library can be built on walk a loop whose
    number of iterations follows the operand, so inverting the nonce itself let
    the time that loop took follow the nonce as well.  The countermeasure
    inverts a blinded nonce instead and unblinds the result, which is the same
    value because `(b*k)^-1 * b` is `k^-1` modulo the order for every factor
    `b` invertible there, so nothing the caller sees changes; what changes is
    that the loop now follows a factor that is not the nonce.

    The algebra that makes the blinding invisible from the outside is asserted
    separately, by the test of `TestSignatureTransparency` named for the
    blinding cancelling exactly.

    The factor is *drawn*, not derived, and drawn again for every signature.
    That is the whole point of it: a factor computed from the key and the nonce
    would be one fixed value per key and nonce, so signing the same digest with
    the same nonce twice would walk the very same loop twice and an attacker
    able to ask for that could average the measurement noise away and be left
    with a time that follows the secret after all.  Only fresh randomness makes
    the operand handed to the inversion -- and with it the number of iterations
    the loop runs, where it runs one -- a different value on every signature.

    The price is disclosed rather than avoided: signing now reads the entropy
    source even when the caller supplied the nonce itself, and a refusal of that
    source is reported as the `RuntimeError` the low level method has always
    documented.  Falling back to an unblinded inversion instead would let
    whoever can exhaust the source switch the countermeasure off, and deriving
    the factor to avoid the read would put a repeatable value back where a fresh
    one is needed.  What a caller fixing the randomness of a signature still
    gets is the signature it always got, byte for byte, because the factor
    cancels; what it does not get is a signing operation that reads nothing.

    That the source is read says only that a factor was drawn -- an
    implementation that drew one and then inverted the nonce itself would
    satisfy every assertion about the value of a signature, because the blinding
    cancels and leaves the signature exactly as it was.  What the inversion is
    handed therefore has to be asserted directly, which is what
    `test_the_inversion_is_given_the_blinded_nonce_and_not_the_nonce` and
    `test_the_blinded_operand_differs_across_repeated_signatures` do.

    Every test here goes through `ecdsa.ecdsa.Private_key` rather than through
    `ecdsa.keys.SigningKey` where it can, because the blinding lives in the low
    level signing method; the ones that are about what a caller can observe go
    through the public key classes as well, because that is where a caller is.
    Each test that stands in for the source or for the inversion restores it in
    a `finally` block and then asserts that it was restored, because one left
    standing in for would break every test that runs after it.
    """

    # a fixed private scalar, a fixed nonce and a fixed message, all narrower
    # than the order of the curve used here.  Nothing about them is secret, and
    # no test depends on their values: what is asserted is where the factor
    # comes from, what is done with it, and that it is not the same twice.
    SECRET = scalars_of_width(200, 1, seed=31)[0]
    NONCE = scalars_of_width(192, 1, seed=32)[0]
    MESSAGE = int("1f2e3d4c5b6a7988", 16)

    # A curve whose generator order is composite, for the one branch that a
    # curve of this library cannot reach.  `util.randrange()` answers with a
    # value in ``[1, n)``, so on the prime orders of every registered curve
    # every value it can possibly answer with is already coprime with the order
    # and the rejection below is unreachable there -- and standing in for the
    # source with a value it could never return, zero, would assert the
    # behaviour of a collaborator that does not exist.  This generator has order
    # 20, so 2, 4, 5, 10 and their multiples are values the real `randrange()`
    # can and does return and which the rejection must catch.  The scalar, nonce
    # and message are chosen so that the signature exists and verifies: on a
    # composite order the nonce and `s` have to be invertible too, which is a
    # property of the curve and not of the blinding.
    COMPOSITE_ORDER = 20
    COMPOSITE_SECRET = 3
    COMPOSITE_NONCE = 7
    COMPOSITE_MESSAGE = 11
    # the signature that key, nonce and message give.  It is a fixed value
    # because the blinding cancels, so it is written out rather than recomputed:
    # a change that let the factor through into the result would be caught here
    # rather than quietly agreed with.
    COMPOSITE_SIGNATURE = (16, 17)
    # two factors of the composite order above, one of which cannot blind an
    # inversion modulo it and one of which can.  Both are values the real
    # `randrange(20)` can return, which is what makes the rejection they drive
    # the behaviour of a collaborator that exists.
    COMPOSITE_REFUSED = 10
    COMPOSITE_ACCEPTED = 3

    def private_key(self):
        """
        A low level private key over NIST256p for the fixed scalar above.

        :return: the private key
        :rtype: ecdsa.ecdsa.Private_key
        """
        generator = NIST256p.generator
        return Private_key(
            Public_key(generator, generator * self.SECRET), self.SECRET
        )

    def composite_order_private_key(self):
        """
        A low level private key whose generator order is composite.

        :return: the private key
        :rtype: ecdsa.ecdsa.Private_key
        """
        generator = PointJacobi(
            CurveFp(23, 2, 2), 0, 5, 1, self.COMPOSITE_ORDER, True
        )
        # a generator of the order it claims, so the key can be built at all
        self.assertEqual(generator * self.COMPOSITE_ORDER, INFINITY)
        return Private_key(
            Public_key(generator, generator * self.COMPOSITE_SECRET),
            self.COMPOSITE_SECRET,
        )

    def composite_signature(self, private_key):
        """Sign the fixed message with the fixed nonce on that key."""
        return private_key.sign(self.COMPOSITE_MESSAGE, self.COMPOSITE_NONCE)

    def drawn_factors(self, order, count):
        """
        Stand in for the source so that the factors it offers are known.

        Answers a callable of the shape `util.randrange()` has, handing out each
        of `count` freshly generated factors once and refusing to be asked more
        often than that, together with the list the orders it was asked for are
        recorded in and the factors themselves.

        The factors are coprime with `order` and differ from each other and from
        one, so that a signature cannot come out right by the factor being
        ignored.

        :param int order: the order the factors are drawn modulo
        :param int count: how many factors to prepare

        :return: the stand-in, the list of recorded orders, and the factors
        :rtype: tuple
        """
        factors = []
        seed = 41
        while len(factors) < count:
            value = scalars_of_width(200, 1, seed=seed)[0] % order
            seed += 1
            if value > 1 and gcd(value, order) == 1 and value not in factors:
                factors.append(value)
        asked = []

        def offer_each_factor_once(requested_order, entropy=None):
            asked.append(requested_order)
            self.assertLessEqual(len(asked), count)
            return factors[len(asked) - 1]

        return offer_each_factor_once, asked, factors

    def count_entropy_reads(self, action):
        """
        Run `action` and answer how many times randomness was read.

        Every source of randomness this library has goes through
        `os.urandom()`, which `util.randrange()` reaches for when a caller
        hands in no source of its own.  Standing in for it counts the reads and
        is restored afterwards, because a source left standing in for would
        break every test that runs after it.

        :param action: what to run
        :type action: callable

        :return: what `action` answered with, and the number of reads
        :rtype: tuple
        """
        original = os.urandom
        reads = []

        def counting_urandom(count):
            reads.append(count)
            return original(count)

        os.urandom = counting_urandom
        try:
            answer = action()
        finally:
            os.urandom = original

        self.assertIs(os.urandom, original)
        return answer, len(reads)

    def operands_of(self, action, order):
        """
        Run `action` and answer what was inverted modulo `order` while it ran.

        The module reference `ecdsa` holds is stood in for rather than the
        function inside `numbertheory`, because that function object is shared
        with `ellipticcurve`, which inverts a field element every time it scales
        a point; replacing the name only where `ecdsa` reads it records the
        inversions this class is about and leaves the point arithmetic alone.

        :param action: what to run
        :type action: callable
        :param int order: the modulus to keep, the field prime being discarded

        :return: what `action` answered with, and the operands
        :rtype: tuple
        """
        original = ecdsa_module.numbertheory
        seen = []

        ecdsa_module.numbertheory = RecordingNumbertheory(original, seen)
        try:
            answer = action()
        finally:
            ecdsa_module.numbertheory = original

        self.assertIs(ecdsa_module.numbertheory, original)
        return answer, [v for v, modulus in seen if modulus == order]

    def test_signing_inverts_twice_for_every_nonce_alike(self):
        """
        Which two inversions signing performs, told apart by their modulus.

        Signing inverts modulo the prime of the field, to bring the point the
        nonce built into the form its first coordinate can be read off, and
        modulo the order of the generator, which is the nonce.  Only the second
        is blinded, and the test below singles it out by its modulus, so what
        the other one is has to be stated somewhere -- and it has to keep
        happening, or that test would be asserting about a signature that never
        touched a point.

        A nonce of one is the one exception, and it is asserted apart because
        it is the whole residual of the edge case behaviour releases up to
        0.19.1 are kept to.  Inside the multiplication a nonce of one costs
        exactly what every other nonce costs -- `TestEdgeCasePreservation`
        counts the point operations and finds no difference -- but the answer
        those releases gave it, and that this one gives it too, is the very
        generator that was multiplied rather than an equal new point.  The
        generator is already scaled, so reading its first coordinate needs no
        field inversion, while reading that of a point a ladder just built
        needs one.  That missing inversion is the residue, and it is
        unreachable in the sense that matters: an attacker who could see it
        would learn that the nonce is one, which is a value that discloses the
        private key outright the moment it is used, and which a nonce drawn
        from ``[1, n)`` takes with probability one in the order.  It is left
        rather than removed because removing it would mean answering a nonce of
        one with a different object than those releases did, which is a change
        to a public and documented result.
        """
        order = int(NIST256p.order)
        prime = NIST256p.curve.p()
        private_key = self.private_key()
        nonces = [self.NONCE % order, 2, order - 1, order - 2]

        original_inverse_mod = numbertheory_module.inverse_mod
        moduli = []

        def recording_inverse_mod(value, modulus):
            moduli.append(modulus)
            return original_inverse_mod(value, modulus)

        numbertheory_module.inverse_mod = recording_inverse_mod
        try:
            observed = []
            for nonce in nonces:
                del moduli[:]
                private_key.sign(self.MESSAGE, nonce)
                observed.append(list(moduli))
            del moduli[:]
            private_key.sign(self.MESSAGE, 1)
            for_one = list(moduli)
        finally:
            numbertheory_module.inverse_mod = original_inverse_mod

        self.assertIs(numbertheory_module.inverse_mod, original_inverse_mod)
        self.assertEqual(observed, [[prime, order]] * len(nonces))
        # the generator itself comes back for a nonce of one, and it needs no
        # scaling, so only the blinded inversion of the nonce happens
        self.assertEqual(for_one, [order])
        self.assertIs(
            private_key.public_key.generator * 1,
            private_key.public_key.generator,
        )

    def test_the_module_draws_the_factor_from_its_own_source(self):
        """
        Where the factor comes from, pinned by name rather than by effect.

        The signing module reaches for `util.randrange()`, which reaches for
        `os.urandom()` unless it is handed a source, and it is not handed one
        here: the factor is drawn from the module's own source and never from
        anything a caller supplies, so a caller able to fix the randomness of a
        signature cannot thereby switch the blinding off.

        Asserted by name because the alternative leaves no trace in any
        signature.  A factor computed from the key and the nonce -- the shape
        this class once had, with a domain separation tag and a call into
        `rfc6979` -- would satisfy every assertion about the value of a
        signature, because the blinding cancels either way, and would silently
        take away the freshness the tests below are about.  So the derived shape
        is asserted absent as well as the drawn one present.
        """
        self.assertIs(ecdsa_module.randrange, randrange)
        self.assertFalse(hasattr(ecdsa_module, "_BLINDING_TAG"))
        self.assertFalse(hasattr(Private_key, "_blinding_factor"))
        # the derivation the factor is not: reached through neither of the two
        # names it would have needed
        self.assertFalse(hasattr(ecdsa_module, "rfc6979"))
        self.assertFalse(hasattr(ecdsa_module, "number_to_string"))

    def test_signing_reads_the_entropy_source_for_every_signature(self):
        """
        The price of a fresh factor, disclosed rather than avoided.

        Four ways of asking for a signature that is a function of its inputs
        alone: the low level method with the nonce handed in, the deterministic
        signing of RFC 6979, deterministic signing of a digest, and signing with
        the caller's own entropy source.  Every one of them now reads the
        operating system, because the factor is drawn there and the nonce being
        fixed does not fix the factor -- and every one of them still answers
        with the same bytes twice, because the factor cancels.

        Both halves matter.  Without the reads the factor would be repeatable
        and the loop it is there to decouple would walk the same path twice;
        without the identical answers the countermeasure would have changed a
        documented result.  The fourth case makes the point sharpest: the caller
        supplied a source of its own for the nonce, and the factor was still
        drawn from the module's, so a caller cannot reach the factor even by
        handing in the randomness of everything else.
        """
        order = int(NIST256p.order)
        private_key = self.private_key()
        signing_key = SigningKey.from_secret_exponent(self.SECRET, NIST256p)
        digest = hashlib.sha256(b"a message to be signed").digest()

        def caller_entropy(requested):
            """A source of the caller's own, and a constant one."""
            return b"\x5b" * requested

        low_level, reads = self.count_entropy_reads(
            lambda: private_key.sign(self.MESSAGE, self.NONCE % order)
        )
        self.assertGreaterEqual(reads, 1)
        again, reads = self.count_entropy_reads(
            lambda: private_key.sign(self.MESSAGE, self.NONCE % order)
        )
        self.assertGreaterEqual(reads, 1)
        self.assertEqual((low_level.r, low_level.s), (again.r, again.s))

        deterministic, reads = self.count_entropy_reads(
            lambda: signing_key.sign_deterministic(
                b"a message", hashfunc=hashlib.sha256
            )
        )
        self.assertGreaterEqual(reads, 1)
        self.assertEqual(
            deterministic,
            signing_key.sign_deterministic(
                b"a message", hashfunc=hashlib.sha256
            ),
        )

        of_a_digest, reads = self.count_entropy_reads(
            lambda: signing_key.sign_digest_deterministic(
                digest, hashfunc=hashlib.sha256
            )
        )
        self.assertGreaterEqual(reads, 1)
        self.assertEqual(
            of_a_digest,
            signing_key.sign_digest_deterministic(
                digest, hashfunc=hashlib.sha256
            ),
        )

        of_caller_entropy, reads = self.count_entropy_reads(
            lambda: signing_key.sign_digest(digest, entropy=caller_entropy)
        )
        self.assertGreaterEqual(reads, 1)
        self.assertEqual(
            of_caller_entropy,
            signing_key.sign_digest(digest, entropy=caller_entropy),
        )

    def test_a_refusal_of_the_entropy_source_is_reported_as_such(self):
        """
        The one way signing can now fail that it could not fail before.

        Blinding the inversion with a drawn factor makes signing depend on the
        entropy source even when the caller supplied the nonce itself, and a
        source is a thing that can decline.  A refusal is reported as the
        `RuntimeError` this method has always documented, rather than let out as
        the error of the source: `sign_digest_deterministic()` retries
        `RSZeroError` and nothing else, so reporting that here would loop for
        ever, and falling back to an unblinded inversion would let whoever can
        exhaust the source switch the countermeasure off.

        Both refusals a source can raise are covered -- `EnvironmentError`,
        which is `OSError` on Python 3, and the `NotImplementedError` a Python 2
        `os.urandom()` raises where it has no source at all -- and both a nonce
        handed in and a nonce derived, because the second reads no randomness
        for its nonce and would otherwise look like a path that never draws.
        The message names the entropy source, so a caller told to retry with a
        new nonce can tell the two `RuntimeError`s apart.
        """
        order = int(NIST256p.order)
        private_key = self.private_key()
        signing_key = SigningKey.from_secret_exponent(self.SECRET, NIST256p)

        def refuse(requested_order, entropy=None):
            raise EnvironmentError("no entropy source here")

        def refuse_as_unimplemented(requested_order, entropy=None):
            raise NotImplementedError("no entropy source at all")

        original = ecdsa_module.randrange
        for refusal in (refuse, refuse_as_unimplemented):
            ecdsa_module.randrange = refusal
            try:
                try:
                    private_key.sign(self.MESSAGE, self.NONCE % order)
                    self.fail("a signature was produced without randomness")
                except RuntimeError as error:
                    self.assertIn("entropy", str(error))
                try:
                    signing_key.sign_deterministic(
                        b"a message", hashfunc=hashlib.sha256
                    )
                    self.fail("a signature was produced without randomness")
                except RuntimeError as error:
                    self.assertIn("entropy", str(error))
            finally:
                ecdsa_module.randrange = original

        self.assertIs(ecdsa_module.randrange, original)
        # and with the source answering again, both of them sign
        self.assertNotEqual(
            private_key.sign(self.MESSAGE, self.NONCE % order).s, 0
        )
        derived = signing_key.sign_deterministic(
            b"a message", hashfunc=hashlib.sha256
        )
        self.assertEqual(
            derived,
            signing_key.sign_deterministic(
                b"a message", hashfunc=hashlib.sha256
            ),
        )
        self.assertTrue(
            signing_key.get_verifying_key().verify(
                derived, b"a message", hashfunc=hashlib.sha256
            )
        )

    def test_every_signature_draws_a_factor_of_its_own(self):
        """
        The freshness of the factor, observed rather than argued.

        Signing the same digest with the same nonce twice gives the same bytes,
        which is necessary but not sufficient: a factor drawn once and cached, or
        one fixed at import, or one computed from the key and the nonce would
        give the same bytes too.  What separates those is how often the source is
        read and what is done with what it offers, so the source is stood in for
        by one that hands out a different valid factor each time it is asked.

        Two signatures then have to read it exactly twice, take a different
        factor each, and still come out byte for byte identical -- identical
        because the factor cancels, twice because it is not kept.  Exactly twice
        and not more, because a factor drawn per point operation would be a
        different implementation with a different cost.
        """
        private_key = self.private_key()
        order = int(NIST256p.order)
        nonce = self.NONCE % order
        expected = private_key.sign(self.MESSAGE, nonce)
        offer, asked, factors = self.drawn_factors(order, 2)
        self.assertNotEqual(factors[0], factors[1])

        original = ecdsa_module.randrange
        ecdsa_module.randrange = offer
        try:
            first = private_key.sign(self.MESSAGE, nonce)
            second = private_key.sign(self.MESSAGE, nonce)
        finally:
            ecdsa_module.randrange = original

        self.assertIs(ecdsa_module.randrange, original)
        # exactly one draw per signature, of the order of the generator: not
        # none, which a cached or derived factor would give, and not more
        self.assertEqual(asked, [order, order])
        # and the two distinct factors produced one and the same signature
        self.assertEqual((first.r, first.s), (second.r, second.s))
        self.assertEqual((first.r, first.s), (expected.r, expected.s))

    def test_the_blinded_operand_differs_across_repeated_signatures(self):
        """
        The property a factor computed from the key and the nonce would lose.

        Nothing is stood in for here except the recording of the inversion: the
        real source draws the real factor, the same key signs the same message
        with the same nonce eight times over, and what the inversion modulo the
        order was handed is collected from each of them.  Every one of the eight
        operands has to be a different value, and none of them may be the nonce.

        This is the assertion that makes the blinding a countermeasure.  A
        repeatable factor -- one derived from the key and the nonce, say -- gives
        the same operand every time, so the loop that inverts it walks the same
        path every time, so an attacker who can ask for the same signature
        repeatedly averages the measurement noise away and is left with a time
        that follows the secret after all.  Eight distinct operands mean there is
        no such path to average.  The eight signatures are identical all the
        same, which is what the freshness costs the caller: nothing.
        """
        order = int(NIST256p.order)
        private_key = self.private_key()
        nonce = self.NONCE % order
        rounds = 8

        seen = []
        signatures = []
        for _ in range(rounds):
            signature, operands = self.operands_of(
                lambda: private_key.sign(self.MESSAGE, nonce), order
            )
            self.assertEqual(len(operands), 1)
            seen.append(operands[0])
            signatures.append((signature.r, signature.s))

        self.assertEqual(len(seen), rounds)
        # a fresh factor per signature, so a fresh operand per signature
        self.assertEqual(len(set(seen)), rounds)
        # and never the nonce itself, which is what was inverted before
        self.assertNotIn(nonce, seen)
        for operand in seen:
            self.assertTrue(1 <= operand < order)
        # the caller sees one signature, eight times over
        self.assertEqual(len(set(signatures)), 1)
        self.assertTrue(
            private_key.public_key.verifies(
                self.MESSAGE, private_key.sign(self.MESSAGE, nonce)
            )
        )

    def test_the_entropy_source_cannot_offer_a_factor_out_of_range(self):
        """
        What the collaborator the tests here stand in for can answer with.

        Recorded because it is what makes the rejection of a factor reachable
        only on a composite order: `util.randrange()` answers with a value in
        ``[1, n)``, never zero and never the order itself, so on a prime order
        every answer is coprime with it already.
        """
        for order in (self.COMPOSITE_ORDER, int(SECP160r1.order)):
            drawn = set(randrange(order) for _ in range(200))
            self.assertTrue(drawn)
            self.assertNotIn(0, drawn)
            for value in drawn:
                self.assertTrue(1 <= value < order)

    def test_the_factor_can_blind_and_unblind_on_every_curve(self):
        """
        The two properties the drawn factor has to have, wherever it is used.

        In range, so that multiplying by it and reducing stays in the group, and
        invertible modulo the order, or `(b*k)^-1 * b` would not be `k^-1` and
        the signature would come out wrong rather than merely slow.

        Asserted across the curves rather than on one, because the factor is
        drawn modulo the order of whichever generator is signing and has to
        answer within it for every order the library ships -- the shortest of
        them, 112 bits, and the longest, 521.  The signature the real source
        produces is verified on each, which is the end to end statement that the
        algebra holds for a factor nobody chose.
        """
        for curve in (SECP112r2, NIST256p, BRAINPOOLP384r1, Ed25519):
            order = int(curve.order)
            secret = self.SECRET % (order - 1) + 1
            generator = curve.generator
            private_key = Private_key(
                Public_key(generator, generator * secret), secret
            )
            for nonce in [1, 2, order - 1, order // 3, self.NONCE % order]:
                label = "%s nonce %d" % (curve.name, nonce)
                factor = randrange(order)
                self.assertTrue(1 <= factor < order, label)
                self.assertEqual(gcd(factor, order), 1, label)
                self.assertEqual(
                    inverse_mod(factor * nonce % order, order)
                    * factor
                    % order,
                    inverse_mod(nonce, order),
                    label,
                )
                signature = private_key.sign(self.MESSAGE % order, nonce)
                self.assertTrue(
                    private_key.public_key.verifies(
                        self.MESSAGE % order, signature
                    ),
                    label,
                )

    def test_a_factor_that_cannot_be_used_is_drawn_again(self):
        """
        The rejection branch, on the one order that can reach it.

        A factor sharing a divisor with the order cannot be inverted, so it
        cannot be unblinded and has to be drawn again.  On a prime order every
        value in ``[1, n)`` is coprime with it, so no curve of this library
        reaches the branch and it is asserted on a composite order instead --
        with factors the real `randrange()` of that order can genuinely return,
        because standing in with a value it could never offer would assert the
        behaviour of a collaborator that does not exist.

        Ten is in range and shares a divisor with twenty, so it is refused;
        three is in range and coprime, so it is taken.  The rejection therefore
        depends on freshly drawn randomness and never on the nonce, and it
        leaves no trace in the result: the signature is the one the accepted
        factor produces, which is the one an unblinded inversion of the same
        nonce would have produced too.
        """
        order = self.COMPOSITE_ORDER
        private_key = self.composite_order_private_key()
        refused, accepted = self.COMPOSITE_REFUSED, self.COMPOSITE_ACCEPTED
        self.assertTrue(1 <= refused < order)
        self.assertTrue(1 <= accepted < order)
        self.assertNotEqual(gcd(refused, order), 1)
        self.assertEqual(gcd(accepted, order), 1)

        original = ecdsa_module.randrange
        asked = []

        def offer_a_useless_factor_first(requested_order, entropy=None):
            asked.append(requested_order)
            return refused if len(asked) == 1 else accepted

        ecdsa_module.randrange = offer_a_useless_factor_first
        try:
            signature = self.composite_signature(private_key)
        finally:
            ecdsa_module.randrange = original

        self.assertIs(ecdsa_module.randrange, original)
        # the branch was taken exactly once, and it drew again rather than fail
        self.assertEqual(asked, [order] * 2)
        self.assertEqual((signature.r, signature.s), self.COMPOSITE_SIGNATURE)
        # what the same signature is without any blinding at all
        point = private_key.public_key.generator * self.COMPOSITE_NONCE
        unblinded = (
            inverse_mod(self.COMPOSITE_NONCE, order)
            * (
                self.COMPOSITE_MESSAGE
                + self.COMPOSITE_SECRET * (point.x() % order)
            )
            % order
        )
        self.assertEqual(
            (signature.r, signature.s), (point.x() % order, unblinded)
        )
        self.assertTrue(
            private_key.public_key.verifies(self.COMPOSITE_MESSAGE, signature)
        )
        # and the real source signs that key too, whatever it happens to draw
        self.assertEqual(
            (
                self.composite_signature(private_key).r,
                self.composite_signature(private_key).s,
            ),
            self.COMPOSITE_SIGNATURE,
        )

    def test_no_factor_is_passed_over_on_the_orders_that_are_prime(self):
        """
        The rejection branch is not taken on any curve this library ships.

        Which is why the test above needs a curve of its own, and is worth
        asserting here because it is what makes the branch above the only
        untaken one: the first factor drawn is the factor used, on every
        registered order, so a signature costs one draw and the number of draws
        does not follow the nonce either.

        The stand-in forwards to the real `randrange()` rather than answering
        with a value of its own, so what is counted is the behaviour of the real
        source on a real order.
        """
        order = int(NIST256p.order)
        private_key = self.private_key()
        original = ecdsa_module.randrange

        for nonce in [1, 2, 3, order - 1, self.NONCE % order]:
            asked = []

            def offer_a_usable_factor(requested_order, entropy=None):
                asked.append(requested_order)
                drawn = original(requested_order)
                self.assertEqual(gcd(drawn, requested_order), 1)
                return drawn

            ecdsa_module.randrange = offer_a_usable_factor
            try:
                signature = private_key.sign(self.MESSAGE, nonce)
            finally:
                ecdsa_module.randrange = original

            self.assertIs(ecdsa_module.randrange, original)
            self.assertEqual(asked, [order])
            self.assertTrue(
                private_key.public_key.verifies(self.MESSAGE, signature)
            )

    def test_the_inversion_is_given_the_blinded_nonce_and_not_the_nonce(self):
        """
        What the loop the countermeasure is about actually walks.

        Every other assertion here is about the factor; this one is about the
        operand, which is what the timing of the inversion follows and therefore
        the only thing that makes the blinding a countermeasure rather than an
        unused computation.  The module reference `ecdsa` holds is stood in for
        and the inversion modulo the order is picked out of what it was called
        with -- the other one, modulo the prime of the field, belongs to reading
        the first coordinate of a point and is not blinded.

        The operand has to be the nonce multiplied by the factor the source
        offered and reduced, and it has to differ from the nonce, and the
        signature has to come out unchanged all the same.  An implementation
        that drew a factor and then inverted the bare nonce would pass every
        other test in this class and fail this one.
        """
        order = int(NIST256p.order)
        private_key = self.private_key()
        nonce = self.NONCE % order
        offer, asked, factors = self.drawn_factors(order, 1)
        factor = factors[0]

        original = ecdsa_module.randrange
        ecdsa_module.randrange = offer
        try:
            signature, operands = self.operands_of(
                lambda: private_key.sign(self.MESSAGE, nonce), order
            )
        finally:
            ecdsa_module.randrange = original

        self.assertIs(ecdsa_module.randrange, original)
        self.assertEqual(asked, [order])
        # the nonce itself is never handed to the inversion; the nonce times
        # the factor the source offered is
        self.assertEqual(operands, [factor * nonce % order])
        self.assertNotEqual(operands[0], nonce)
        # and the signature is still the one the bare inversion would give
        unblinded = private_key.sign(self.MESSAGE, nonce)
        self.assertEqual(
            (signature.r, signature.s), (unblinded.r, unblinded.s)
        )
        self.assertTrue(
            private_key.public_key.verifies(self.MESSAGE, signature)
        )


class TestEdgeCasePreservation(unittest.TestCase):
    """
    The multipliers and the points the countermeasure has to leave alone.

    Zero, one, the order of a point, multiples of it and one less than it give
    exactly the points they gave before, on a generator whose multiplication
    table is filled, on one whose table is empty, on a point that is not a
    generator at all -- the shape an ECDH exchange multiplies -- and on a point
    that knows no order.  Every equality in this class was measured to hold on
    the unmodified 0.19.1+2.g55aca78 tree as well; that is precisely what it is
    for, and a difference in any of them would be a change in behaviour the
    countermeasure had no licence to make.

    What the countermeasure does change, deliberately, is *how* those points
    are arrived at, and this class keeps the two apart.  A point whose order the
    fixed length recoding can use no longer decides from its multiplier whether
    to run a ladder at all: zero and one used to be answered ahead of one, in no
    point operations, where every other multiplier cost the full fixed number,
    which is exactly the short circuit CVE-2024-23342 is about -- and a
    multiplier of one is not hypothetical, `SigningKey.sign_number()` accepting
    any nonce from one up.  Both of them now cost what every other multiplier
    costs, as `test_the_edge_multipliers_cost_what_every_multiplier_costs`
    asserts, and which of two ready answers a caller is handed is picked out by
    index once that work is done.  So the answers themselves are the ones those
    releases gave, down to the identity of the object: the very point that was
    multiplied for a multiplier of one, and the point at infinity for a
    multiplier of zero.  A point whose order is too small for the recoding, or
    which knows no order at all, keeps the shortcuts, the reduction modulo
    twice the order and the ladder releases up to 0.19.1 drove with it, which
    no other test in this file visits.
    """

    # the curve the advisory names and the smallest registered curve, which
    # keeps this class inside the fast selection
    EDGE_CURVES = (NIST256p, SECP160r1)

    def points_of(self, curve):
        """
        The four shapes of point of `curve` a multiplication can be handed.

        Each is labelled, so that a failure names the shape it happened on
        rather than leaving it to be guessed from a coordinate.

        :param curve: the curve to build the points on

        :return: pairs of a label and a point
        :rtype: tuple of tuple of str and point
        """
        return (
            ("the shared generator", warm_generator(curve)),
            ("a generator with an empty table", rebuilt_generator(curve)),
            (
                "a point that is not a generator",
                rebuilt_generator(curve, False),
            ),
            ("a point that knows no order", order_less_point(curve)),
        )

    def test_a_multiplier_of_zero_gives_the_point_at_infinity(self):
        """Through the ladder on a hardened point, through a guard otherwise."""
        for curve in self.EDGE_CURVES:
            for label, point in self.points_of(curve):
                self.assertIs(point * 0, INFINITY, label)

    def test_a_multiplier_of_one_gives_the_very_same_point(self):
        """
        The object that was multiplied, on every shape of point.

        A point whose order the recoding can use runs its ladder for this
        multiplier like for any other, so the work is done -- but the answer
        handed back is still the object that was multiplied, picked out by index
        once the ladder has finished.  It is the only result that carries the
        order the point knows, its generator flag and its multiplication table,
        which is why releases up to 0.19.1 answered with it and why this keeps
        doing so.
        """
        for curve in self.EDGE_CURVES:
            for label, point in self.points_of(curve):
                product = point * 1
                self.assertIs(product, point, label)
                self.assertEqual(product.order(), point.order(), label)

    def test_the_order_and_its_multiples_give_the_point_at_infinity(self):
        """
        Reached through the ladder, not through a guard.

        None of these multipliers is zero, so each of them is normalised and
        driven through a ladder, which has to arrive at the point at infinity
        on its own -- the check a ladder ends with is the only thing that can
        report it.  `test_jacobi` pins the same claim for a multiplier of the
        order through the examples its property test carries.
        """
        for curve in self.EDGE_CURVES:
            order = int(curve.order)
            for label, point in self.points_of(curve):
                for scalar in (order, 2 * order, 3 * order, -order):
                    self.assertEqual(point * scalar, INFINITY, label)

    def test_one_less_than_the_order_gives_the_negated_point(self):
        for curve in self.EDGE_CURVES:
            order = int(curve.order)
            generator = curve.generator
            for label, point in self.points_of(curve):
                product = point * (order - 1)
                self.assertEqual(product, -generator, label)
                self.assertEqual(product + generator, INFINITY, label)

    def test_a_negative_multiplier_negates_the_product(self):
        """
        Negative multipliers are answered as they always were.

        `test_ellipticcurve` asserts the same of the affine implementation; it
        is repeated here for the Jacobi one because the normalising step is
        handed the negative value and has to bring it inside the order before
        any digit is read off it.
        """
        for curve in self.EDGE_CURVES:
            for label, point in self.points_of(curve):
                self.assertEqual(point * -5, (-point) * 5, label)
                self.assertEqual(point * -5, -(point * 5), label)
                self.assertEqual((point * -5) + (point * 5), INFINITY, label)

    def test_a_multiplier_that_is_not_a_number_but_is_false(self):
        """
        `False` is a zero; a `None` is refused rather than read as one.

        `False` is an integer in Python, is recoded like any other multiplier,
        and comes out as the zero it stands for.  A `None` is not an integer and
        has no bits for a recoding to read, so it is refused by the normalising
        step every multiplication starts with rather than being read as the zero
        releases up to 0.19.1 read it as -- see `TestMultiplierNormalisation`,
        which covers that step and the rest of these values.
        """
        for curve in self.EDGE_CURVES:
            for label, point in self.points_of(curve):
                self.assertEqual(point * False, INFINITY, label)
                self.assertRaises(TypeError, point.__mul__, None)

    def test_a_multiplier_of_true_is_answered_like_a_one(self):
        """A boolean is an integer, so it is answered as the one it stands."""
        for curve in self.EDGE_CURVES:
            for label, point in self.points_of(curve):
                self.assertEqual(point * True, point, label)
                self.assertEqual(point * True, point * 1, label)

    def test_the_edge_multipliers_cost_what_every_multiplier_costs(self):
        """
        The other half of the separation, and the reason for it.

        Zero, one, the order, one more and one less than it, and a full width
        multiplier all cost the same number of point additions and point
        doublings on a point whose order the recoding can use -- with a table
        and without one.  This is the assertion the shortcuts this class used to
        pin would fail: with them in place a multiplier of one cost no point
        operation at all, which is a difference in run time an attacker reads
        off directly.
        """
        window = ellipticcurve._MUL_WINDOW
        for curve in self.EDGE_CURVES:
            order = int(curve.order)
            digits, _ = fixed_ladder_shape(order)
            point_class = point_class_of(curve)
            scalars = [0, 1, 2, order - 1, order, order + 1]
            scalars.extend(scalars_of_width(bit_length(order), 1, seed=11))
            shapes = (
                ("with a table", warm_generator(curve), (digits, 0)),
                (
                    "without a table",
                    rebuilt_generator(curve, False),
                    (
                        digits + (1 << (window - 1)) - 1,
                        (digits - 1) * window + 1,
                    ),
                ),
            )

            for label, point, expected in shapes:
                counted = set()
                for scalar in scalars:
                    _, additions, doublings = count_point_operations(
                        point_class, multiplier(point, scalar)
                    )
                    counted.add((additions, doublings))
                self.assertEqual(sorted(counted), [expected], label)

    def test_the_point_at_infinity_stays_the_point_at_infinity(self):
        """Whatever it is multiplied by, including values it never reads."""
        order = int(NIST256p.order)
        for scalar in (0, 1, 2, 7, order, order - 1, -5):
            self.assertIs(INFINITY * scalar, INFINITY)
        # it is answered from the shape of the point, before the multiplier is
        # read for anything at all, exactly as it was before
        self.assertIs(INFINITY * None, INFINITY)
        self.assertIs(INFINITY * 1.5, INFINITY)

    def test_a_point_at_infinity_that_knows_a_usable_order(self):
        """
        Answered with the point at infinity too, and with the same object.

        `INFINITY` itself carries no order and so takes the fall-back ladder,
        where the shape of the point is tested first.  A point built with no
        coordinates but with an order the recoding can use reaches the fixed
        work path instead, and the same test has to come first there as well:
        there are no coordinates for a ladder to work on, and the integer
        backends that hold coordinates as `mpz` cannot build one from a `None`.
        Releases up to 0.19.1 answered such a point with the very same object
        for every multiplier, a multiplier of one included, and so does this.
        """
        point = Point(None, None, None, SMALLEST_ORDER)
        self.assertTrue(PointJacobi._fixed_ladder_usable(point.order()))
        for scalar in (0, 1, 2, 5, SMALLEST_ORDER, SMALLEST_ORDER + 1, -5):
            self.assertIs(point * scalar, INFINITY, "multiplier %d" % scalar)

    def test_a_point_whose_guarded_coordinate_is_zero(self):
        """
        The other half of the guard that answers a multiplier of zero.

        A Jacobi point tests its second coordinate and an Edwards point its
        first and its fourth, so a point holding a zero in one of those is
        answered with the point at infinity whatever it is multiplied by.  No
        curve of this library produces such a point, but the guard is reachable
        from outside and behaves as it did before.
        """
        generator = NIST256p.generator
        order = int(NIST256p.order)
        flat = PointJacobi(generator.curve(), generator.x(), 0, 1, order)
        for scalar in (2, 5, order, order - 1):
            self.assertEqual(flat * scalar, INFINITY)

        edwards = Ed25519.generator
        edwards_order = int(Ed25519.order)
        flat_edwards = PointEdwards(
            edwards.curve(), 0, edwards.y(), 1, 0, edwards_order
        )
        for scalar in (2, 5, edwards_order):
            self.assertEqual(flat_edwards * scalar, INFINITY)

    def test_a_point_that_knows_no_order_agrees_with_one_that_does(self):
        """
        The two ladders answer every multiplier the same way.

        A point that knows no order cannot have its multiplier normalised, so
        it keeps the ladder whose number of point operations follows the
        multiplier.  That ladder is not hardened, and nothing inside this
        library multiplies a secret by such a point -- a public point decoded
        from an encoding has the order attached by `ecdsa.ecdsa.Public_key`,
        see `TestECDHKeyAgreement` -- but it still has to compute the same
        points as the hardened one.
        """
        for curve in self.EDGE_CURVES:
            order = int(curve.order)
            known = warm_generator(curve)
            unknown = order_less_point(curve)
            for scalar in (2, 3, 7, order - 1, order + 1, 2 * order + 3):
                self.assertEqual(unknown * scalar, known * scalar)

    def test_the_affine_implementation_agrees_at_every_edge(self):
        """
        The oldest of the four multiplications, at the same edges.

        A point in affine coordinates whose order the fixed length recoding can
        use hands its work to the Jacobi implementation and converts the result
        back, and one whose order it cannot use keeps the X9.62 D.3.2 ladder.
        Both are asserted here against the same edges as the Jacobi points, and
        against the Jacobi results themselves.  The hand-off is unconditional,
        so a multiplier of one pays for a ladder here as well -- and, as there,
        is still answered with the very point that was multiplied, order
        included, once that ladder has run.
        """
        for curve in self.EDGE_CURVES:
            order = int(curve.order)
            jacobi = warm_generator(curve)
            affine = Point(jacobi.curve(), jacobi.x(), jacobi.y(), order)
            order_less = Point(jacobi.curve(), jacobi.x(), jacobi.y())

            self.assertEqual(affine * 0, INFINITY)
            self.assertIs(affine * 1, affine)
            self.assertEqual((affine * 1).order(), order)
            self.assertIs(affine * True, affine)
            self.assertEqual(affine * order, INFINITY)
            self.assertEqual(affine * (2 * order), INFINITY)
            self.assertEqual(affine * (order - 1), -affine)
            self.assertEqual(affine * -5, (-affine) * 5)

            self.assertEqual(order_less * 0, INFINITY)
            self.assertIs(order_less * 1, order_less)
            self.assertEqual(order_less * order, INFINITY)
            self.assertEqual(order_less * -5, (-order_less) * 5)

            for scalar in (2, 3, 7, order - 1):
                self.assertEqual(affine * scalar, jacobi * scalar)
                self.assertEqual(order_less * scalar, jacobi * scalar)

    def test_an_order_too_small_for_the_recoding_keeps_the_old_ladder(self):
        """
        The one point shape that still reduces modulo twice the order.

        The fixed length recoding needs an order wider than a window and odd,
        and the curve of 23 points `test_ellipticcurve` uses gives a point of
        order 7, which is odd but far too narrow.  Such a point keeps the
        reduction modulo twice the order and the ladder releases up to 0.19.1
        drove with it, and has to keep answering what they answered.  Nothing
        about it is hardened: a caller who builds a point on a curve of this
        size and multiplies it by a value of their own gets a number of point
        operations that follows that value.  What holds is the narrower claim,
        that no route through the registered curves and the high level entry
        points of this library reaches such a point with a secret, since every
        curve this library registers declares an order the recoding can use.
        That an order of seven is refused is asserted by
        `TestCanonicalScalar.test_which_orders_the_fixed_length_ladder_refuses`
        rather than here, so that every assertion of this class remains one
        that held before the countermeasure as well.
        """
        curve = CurveFp(23, 1, 1)
        jacobi = PointJacobi(curve, 13, 7, 1, 7)
        affine = Point(curve, 13, 7, 7)

        for scalar in range(0, 15):
            self.assertEqual(
                jacobi * scalar, affine * scalar, "multiplier %d" % scalar
            )
        self.assertEqual(jacobi * 0, INFINITY)
        self.assertEqual(jacobi * 7, INFINITY)
        self.assertEqual(jacobi * 14, INFINITY)
        self.assertEqual(jacobi * 8, jacobi)
        self.assertEqual(jacobi * -5, (-jacobi) * 5)
        self.assertEqual(precompute_table(jacobi), [])

    def test_the_edwards_implementation_agrees_at_every_edge(self):
        """
        The same edges on the twisted Edwards points, which EdDSA signs with.

        The Edwards implementation received the same treatment as the Jacobi
        one and has to preserve the same behaviour.  One less than the order is
        stated as the point that leaves the point at infinity when the
        generator is added back to it, since these points offer no unary
        negation.  A `None` is refused here as it is everywhere else, the
        normalising step coming ahead of every ladder on this class too.
        """
        order = int(Ed25519.order)
        generator = warm_generator(Ed25519)
        points = (
            ("the shared generator", generator),
            ("a generator with an empty table", rebuilt_generator(Ed25519)),
            (
                "a point that is not a generator",
                rebuilt_generator(Ed25519, False),
            ),
            ("a point that knows no order", order_less_point(Ed25519)),
        )
        for label, point in points:
            self.assertEqual(point * 0, INFINITY, label)
            self.assertIs(point * 1, point, label)
            self.assertIs(point * True, point, label)
            self.assertRaises(TypeError, point.__mul__, None)
            self.assertEqual(point * order, INFINITY, label)
            self.assertEqual(point * (2 * order), INFINITY, label)
            self.assertEqual(point * (-order), INFINITY, label)
            self.assertEqual(
                (point * (order - 1)) + generator, INFINITY, label
            )
            self.assertEqual((point * -5) + (point * 5), INFINITY, label)
            self.assertEqual(point * 7, generator * 7, label)
            self.assertEqual(point * (order + 3), generator * 3, label)

    def test_the_edwards_points_still_offer_no_negation(self):
        """
        Recorded because the assertions above have to work around it.

        A twisted Edwards point of this library cannot be negated with the
        unary operator, which is why one less than the order is stated through
        an addition instead.  Negating a multiplier is a different matter and
        is answered, as the assertions above show.
        """

        def negate():
            return -Ed25519.generator

        self.assertRaises(TypeError, negate)


class TestMultiplierNormalisation(unittest.TestCase):
    """
    A multiplier that is not an integer is refused rather than truncated.

    Unlike the class above this describes behaviour the countermeasure
    introduced, and it is asserted here because everything the countermeasure
    derives from a multiplier is integer arithmetic: the recodings read the
    bits of the multiplier with shifts, masks and divisions, so a value that
    merely converts to an integer -- the decimal digits of a string, or a float
    truncated towards zero -- would multiply a point by a number its caller
    never asked for, and a value that does not convert at all would surface as
    whichever error the first arithmetic operation happened to raise, which
    differs between the three integer implementations this module can be built
    on.  Asking the multiplier for its lossless integer value refuses both with
    one and the same exception.

    The step that asks is `AbstractPoint._integer_multiplier()`, and it comes
    ahead of everything else a multiplication does with the multiplier -- ahead
    of the choice of ladder, ahead of the shortcut for a multiplier of zero and
    of one.  It has to: it reads the *type* of the multiplier and never its
    value, so a value that reached a ladder without passing through it would be
    a value the work of a multiplication could be told apart by, which is the
    property CVE-2024-23342 is about.  Reading only the type is also what makes
    the refusal uniform: `int`, `bool` and the ``mpz`` of both gmpy releases are
    accepted whatever they hold, and everything else is refused whatever it
    holds, so no assertion in this file depends on which of the three integer
    backends the module was built on.

    Releases up to 0.19.1 answered some of these values and refused the rest,
    each by whichever operation happened to reach it first, so the refusal here
    is a new exception on a public operation for the ones they answered and a
    differently worded one for the rest.  That is a deliberate part of the
    change and not an oversight: a float of one used to be answered with the
    point, because the guard for a multiplier of one compared for equality, and
    that guard now sits *behind* the normalising step -- it had to, or a nonce
    of one would never reach a ladder at all.

    The point at infinity is the one exception, and it is asserted apart from
    the rest: it is answered before the multiplier is looked at at all, exactly
    as it was before, because that answer reads the point and not the
    multiplier.
    """

    def test_an_integer_is_returned_as_it_is(self):
        for value in (0, 1, 2, -7, 1 << 300):
            self.assertEqual(PointJacobi._integer_multiplier(value), value)

    def test_a_boolean_is_taken_for_the_integer_it_stands_for(self):
        self.assertEqual(PointJacobi._integer_multiplier(True), 1)
        self.assertEqual(PointJacobi._integer_multiplier(False), 0)

    def test_a_value_that_offers_a_lossless_integer_is_accepted(self):
        """
        The protocol the accepted types have in common.

        `int`, `bool` and the arbitrary precision integers of both gmpy
        releases answer it, which is what lets every count asserted in this
        file hold whichever of the three the module was built on.  The classes
        at the top of this file stand in for the two that may not be installed,
        one of them answering with a value far wider than any curve order.
        """
        self.assertEqual(PointJacobi._integer_multiplier(Multiplier()), 11)
        self.assertEqual(
            PointJacobi._integer_multiplier(WideMultiplier()), 1 << 300
        )
        for point_class in (PointJacobi, PointEdwards, Point):
            self.assertEqual(point_class._integer_multiplier(Multiplier()), 11)

    def test_the_integer_backend_of_this_module_is_accepted(self):
        """
        Whichever of the three it was built on, and losslessly.

        `ecdsa.ellipticcurve.GMPY` records whether an ``mpz`` was found, and
        when one was the multiplier a caller hands a multiplication may be one,
        since this module does its own arithmetic with them.  Either way the
        value comes back as a plain `int` of the same magnitude -- the recodings
        that follow index a list with it, which an ``mpz`` cannot be used for on
        every release.
        """
        for value in (0, 1, 7, 1 << 300, int(NIST256p.order)):
            normalised = PointJacobi._integer_multiplier(value)

            self.assertEqual(normalised, value)
            self.assertIsInstance(normalised, int)
        if ellipticcurve.GMPY:
            for value in (0, 1, 7, int(NIST256p.order)):
                normalised = PointJacobi._integer_multiplier(
                    ellipticcurve.mpz(value)
                )

                self.assertEqual(normalised, value)
                self.assertIsInstance(normalised, int)

    def test_a_lossless_integer_that_is_not_an_integer_is_refused(self):
        """
        The other half of the protocol: what ``__index__()`` answers with.

        Asking for the method and calling it accepts whatever it hands back, so
        an implementation answering the string ``"3"`` would have this helper
        return that string, and the normalising step that follows reduces it
        modulo the order to three -- multiplying the point by a number the
        caller never asked for, which is exactly what refusing a multiplier
        that is not an integer is meant to prevent.  `operator.index()` is
        asked instead, and it refuses the answer as well as the absence of the
        method, so the two cases are one and the same `TypeError` here.
        """
        for fixture in (
            StringMultiplier,
            FloatMultiplier,
            NoneMultiplier,
            ListMultiplier,
        ):
            for point_class in (PointJacobi, PointEdwards, Point):
                self.assertRaises(
                    TypeError, point_class._integer_multiplier, fixture()
                )
            # and the message names the type the caller passed rather than the
            # type its `__index__()` answered with
            try:
                PointJacobi._integer_multiplier(fixture())
                self.fail("%s was accepted as a multiplier" % fixture.__name__)
            except TypeError as error:
                self.assertEqual(
                    str(error),
                    "multiplier must be an integer, not %s" % fixture.__name__,
                )

    def test_a_multiplication_refuses_a_malformed_lossless_integer(self):
        """Reached through the operator, on every shape of point."""
        points = (
            warm_generator(NIST256p),
            rebuilt_generator(NIST256p, False),
            order_less_point(NIST256p),
            warm_generator(Ed25519),
            order_less_point(Ed25519),
            Point(
                NIST256p.generator.curve(),
                NIST256p.generator.x(),
                NIST256p.generator.y(),
            ),
        )
        for point in points:
            for fixture in (StringMultiplier, FloatMultiplier):
                self.assertRaises(TypeError, point.__mul__, fixture())
        # the multiplier the string one answers with, had it been accepted
        self.assertNotEqual(
            NIST256p.generator * 3, INFINITY, "the value it would have used"
        )

    def test_a_value_that_is_not_an_integer_is_refused(self):
        values = (1.5, 2.0, "3", None, b"\x01", [1], (1,), complex(1, 0))
        for value in values:
            for point_class in (PointJacobi, PointEdwards, Point):
                self.assertRaises(
                    TypeError, point_class._integer_multiplier, value
                )

    def test_the_refusal_names_the_type_it_refused(self):
        """The three type names both Python 2 and Python 3 spell alike."""
        for value, name in ((1.5, "float"), ("3", "str"), (None, "NoneType")):
            try:
                PointJacobi._integer_multiplier(value)
                self.fail("a %s was accepted as a multiplier" % name)
            except TypeError as error:
                self.assertEqual(
                    str(error),
                    "multiplier must be an integer, not %s" % name,
                )

    def test_a_multiplication_refuses_it_too(self):
        """
        Reached through the operator, on every shape of point.

        Every value that is not an integer reaches the normalising step and is
        refused there, whatever it happens to equal.  A float of one is
        included deliberately: it used to be answered with the point, because
        the guard that answered a multiplier of one compared for equality and a
        float compares equal to the integer it holds.  That guard now sits
        behind the normalising step -- it had to, or a nonce of one would never
        have reached a ladder -- so the value is refused like every other
        non-integer, which is also what a float of two has always been.  A
        complex number of one is refused for the same reason, and a value that
        is merely false -- a `None`, an empty sequence -- is refused rather than
        read as the zero those releases read it as.
        """
        curve = NIST256p
        points = (
            warm_generator(curve),
            rebuilt_generator(curve),
            rebuilt_generator(curve, False),
            order_less_point(curve),
            warm_generator(Ed25519),
            rebuilt_generator(Ed25519, False),
            order_less_point(Ed25519),
        )
        for point in points:
            for value in (
                1.0,
                1.5,
                2.0,
                "3",
                complex(1, 0),
                None,
                [],
                (),
                b"",
                "",
                [1],
                (1,),
                b"\x01",
            ):
                self.assertRaises(TypeError, point.__mul__, value)

    def test_the_affine_multiplication_refuses_it_too(self):
        """
        The affine implementation refuses it in the one place as well.

        Whether the point knows its order or not, the multiplier reaches the
        normalising step before anything is done with it, so the caller is
        handed a `TypeError` rather than a point it never asked for.  Releases
        up to 0.19.1 reduced the multiplier modulo the order of the point
        first, which refused a string and a `None` by way of whichever error
        the reduction happened to raise; a float got as far as the reduction
        itself, and release 1.17 of the older of the two gmpy bindings answers
        a float taken modulo an integer as wide as a curve order by attempting
        an allocation of exabytes and taking the interpreter down with it.
        Normalising first is what closes that off, which is why a float is
        handed to both points here.

        The point at infinity is asserted apart from the two: it is answered
        before the multiplier is looked at at all, exactly as it was before.
        """
        generator = NIST256p.generator
        order = int(NIST256p.order)
        affine = Point(generator.curve(), generator.x(), generator.y(), order)
        order_less = Point(generator.curve(), generator.x(), generator.y())

        for point in (affine, order_less):
            self.assertRaises(TypeError, point.__mul__, "3")
            self.assertRaises(TypeError, point.__mul__, None)
            self.assertRaises(TypeError, point.__mul__, [1])
            self.assertRaises(TypeError, point.__mul__, 1.0)
            self.assertRaises(TypeError, point.__mul__, 1.5)
            self.assertRaises(TypeError, point.__mul__, 2.0)

        self.assertEqual(INFINITY * 1.5, INFINITY)
        self.assertEqual(INFINITY * None, INFINITY)

    def test_the_point_at_infinity_is_answered_before_any_of_this(self):
        """
        It never looks at the multiplier at all, exactly as before.

        `INFINITY` is the affine point with no coordinates and no order, and the
        test for it comes ahead of the normalising step, so a multiplier it is
        handed is neither normalised nor refused.  Both groups of value are
        asserted, since releases up to 0.19.1 answered every one of them here.
        """
        for value in (
            None,
            [],
            (),
            b"",
            "",
            "3",
            [1],
            (1,),
            b"\x01",
            1.5,
            complex(1, 0),
            StringMultiplier(),
            Multiplier(),
        ):
            self.assertEqual(INFINITY * value, INFINITY, repr(value))
        self.assertEqual(INFINITY * 0, INFINITY)
        self.assertEqual(INFINITY * 1, INFINITY)
        self.assertEqual(INFINITY * 12345, INFINITY)

    def test_a_secret_bearing_entry_point_never_hands_over_a_non_integer(self):
        """
        Why refusing them costs this library's own callers nothing.

        Every multiplier the signing, key generation and ECDH paths form is an
        integer: `ecdsa.util.randrange()` and `ecdsa.rfc6979.generate_k()` both
        return one, and `Private_key.sign()` multiplies the generator by the
        nonce it was handed.  Asserted here rather than argued, by signing with
        each of the three curve families and by deriving a shared secret, so
        that a path forming something else would fail this test.
        """
        digest = hashlib.sha256(b"a message to sign").digest()
        for curve in (NIST256p, SECP256k1, BRAINPOOLP256r1):
            signing_key = SigningKey.generate(curve=curve)

            signature = signing_key.sign_digest(digest)
            self.assertTrue(
                signing_key.get_verifying_key().verify_digest(
                    signature, digest
                ),
                curve.name,
            )
            deterministic = signing_key.sign_digest_deterministic(
                digest, hashfunc=hashlib.sha256
            )
            self.assertTrue(
                signing_key.get_verifying_key().verify_digest(
                    deterministic, digest
                ),
                curve.name,
            )
        left, right = (
            SigningKey.generate(curve=NIST256p),
            SigningKey.generate(curve=NIST256p),
        )
        first, second = ECDH(curve=NIST256p), ECDH(curve=NIST256p)
        first.load_private_key(left)
        first.load_received_public_key(right.get_verifying_key())
        second.load_private_key(right)
        second.load_received_public_key(left.get_verifying_key())
        self.assertEqual(
            first.generate_sharedsecret_bytes(),
            second.generate_sharedsecret_bytes(),
        )
        # and an EdDSA signature, whose multiplier is a full hash output
        eddsa_key = EdDSAPrivateKey(Ed25519.generator, os.urandom(32))
        self.assertTrue(
            eddsa_key.public_key().verify(
                b"a message", eddsa_key.sign(b"a message")
            )
        )
