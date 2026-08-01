"""Nonce-bit-length timing probe for the ECDSA signing path.

Stratified wall-clock measurement of ``ecdsa.SigningKey.sign_digest()``
against the bit length of the per-signature nonce, reported with the
statistical battery the external ``tlsfuzzer`` harness applies to the
same question.

Why this script exists
----------------------
The signing path of this library was reported as leaking the bit length
of the per-signature nonce through the wall-clock duration of a
signature:

    CVE-2024-23342 / GHSA-wj6h-64fc-37mp / PYSEC-2026-1325
    CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N -- 7.4 (HIGH)
    CWE-203 (Observable Discrepancy), CWE-208 (Observable Timing
    Discrepancy), CWE-385 (Covert Timing Channel)

An observer who can ask for many signatures under one key, time them
and keep the fastest learns a few high-order bits of each nonce; enough
of those partial leaks assemble into a Hidden Number Problem lattice
that recovers the long-term private scalar.  The quantity to drive down
is therefore the dependence of signing time on ``bit_length(k)``, and
the number that matters is how many timed signatures an observer needs
before that dependence becomes statistically visible.

This script estimates that number.  It re-runs the battery over
prefixes of the observations it collected and reports the earliest of
those configured prefixes at which any test rejects, which brackets the
number from above rather than pinning it: the true threshold lies
between that prefix and the one before it.  Run it before and after a
change to the arithmetic layer and compare the two reports: the collapse
of the per-bucket trend, and the growth of that earliest rejecting
prefix, is the evidence.

What this script does NOT do
----------------------------
It does not certify anything.  Nothing it prints is a claim of
constant-time execution, and no such claim is available for arbitrary
precision integer arithmetic in pure Python -- CPython integers are
variable width and the field arithmetic in ``ellipticcurve.py``
deliberately defers some reductions, so a residual per-operation signal
survives any amount of work at the ladder level.  A smaller measured
signal is a smaller measured signal and nothing more.  For calibration:
GnuTLS still exposed a residual step of roughly 34 ns after hardening
compiled C against the same weakness (CVE-2024-28834, fixed in 3.8.4),
which took 43,190,069 observations to see.

Method
------
Two complementary modes, both driven in-process.  Neither opens a
socket, shells out to a capture tool, needs a privilege, takes a
command line argument or writes a file.

* Mode 1 -- controlled nonce bit widths.  A nonce of an exactly known
  bit width is injected through the documented ``k=`` parameter of
  ``sign_digest()`` and the signature is timed as the minimum of a few
  repetitions.  High signal-to-noise, deterministic bucket membership,
  small sample count.
* Mode 2 -- the reported scenario.  The library draws the nonce itself,
  the signature is timed once, and the nonce is then recovered from the
  signature with the private scalar and used only to bucket the
  observation afterwards.  This is what an observer of a signing oracle
  actually has, so it is the mode whose sample count is quoted.

The statistics mirror ``tlsfuzzer/analysis.py::analyze_bit_sizes`` --
``sign_test``, ``paired_t_test``, ``wilcoxon_test`` and
``bootstrap_test``, each bucket paired against the largest-bit-length
bucket, under a Bonferroni correction of the configured alpha.  They are
hand-rolled here from the standard library on purpose: the probe adds no
new dependency, and the external harness is a separate project that is
deliberately not vendored.

The script lives outside ``src/`` and is not named ``test_*.py``
deliberately: a wall-clock statistical measurement has no place in a
determinism-first unit suite, and pytest must not collect it.  Its
counterpart there asserts point-operation counts, which are exact.

Usage
-----
No arguments and no privileges::

    python minerva_probe.py

Everything tunable is a module-level constant below, and the report
prints all of them.  Raise ``REPEAT`` towards the external harness
default of 100000 for a more sensitive run at proportional cost.

Every one of those constants is checked before anything is timed.  A
value a measurement could not be carried out under -- a count of none
where one is needed, a trim the estimator it labels cannot be computed
at, a cap that throws away more pairs than the interval it feeds
admits, a "prefix" that is really the sample with its tail cut off --
stops the run naming the constant, rather than spending minutes
producing a number that turns out to be a property of the edit.

The exit status says whether there is a report, not whether the report
found anything: ``0`` when every requested curve produced the evidence
it was asked for -- a dependence detected or not -- and ``2`` when the
analysis is unavailable, meaning some of that evidence was never
produced or came out of a collection that cannot be trusted.  Detection
deliberately does not fail the run.  The "before" half of a
before/after comparison has to be collectable, so a leak that this
instrument can still see is a result, not an error, and ``tox -e leak``
stays usable against unhardened arithmetic.  The external harness
spends its exit code 1 on detection instead; the difference is
deliberate, and the closing validity section states which reading
applies.  Exit status ``1`` is reserved for the self check below.

The run begins with a self check of its own verdict paths, on synthetic
inputs and before anything is timed, and stops with a non-zero exit
status if any of them is wrong.  It costs a fraction of a second and
guards the one mistake an instrument like this can make silently:
reporting a reassuring nondetection out of a comparison that never
happened.  Its checks are explicit comparisons rather than ``assert``
statements, so that ``python -O`` cannot remove them.

Reading the output
------------------
* the per-bucket table -- if signing time tracks nonce bit length, the
  medians fall as the bit width falls, monotonically.  Judge that on two
  numbers together, never one: ``rho`` near +1 says the ordering is
  there, and the span expressed in bucket standard errors says whether
  the ordering is bigger than the noise.  An ordering across a span of
  one or two noise widths is what chance produces over a handful of
  buckets; an ordering across tens of noise widths is the leak.  The
  span in microseconds is printed too, and it is the right number for
  the SIZE of the effect -- but not for whether the effect is
  resolvable.  Neither number travels between machines: the standard
  error the span is divided by falls with the observation count and
  depends on the local noise, so the two spans are a within-run scale
  and comparable only across runs configured alike.  Note also that
  removing a dependence on the nonce tightens the noise floor as
  well, so between two runs the microsecond span and the span in
  standard errors move by different factors
* ``smallest detectable N`` -- the headline.  The earliest of the
  configured prefix sizes at which any of the three p-value tests
  rejects at the corrected alpha, so its resolution is the spacing of
  that list; higher is better, and "not detected" -- no configured
  prefix rejected -- is the best this instrument can say, never that
  there is nothing there.  It has four states, and two
  of them are not results: ``unavailable`` when a comparison carried a
  value that is not a finite number, and ``insufficient`` when no
  comparison produced a p-value at all.  Neither is a nondetection --
  an untested sample count bounds nothing -- so "not detected at
  N <= x" is printed only over the prefixes a test actually ran over,
  and x names the largest of those rather than the observation count
* the calibration anchors -- what the same measurement cost elsewhere,
  so a result can be situated without reading anything else
"""

from __future__ import division

import math
import platform
import random
import sys
import timeit

import ecdsa
from ecdsa import ellipticcurve
from ecdsa.curves import curves
from ecdsa.ecdsa import RSZeroError
from ecdsa.keys import SigningKey
from ecdsa.numbertheory import inverse_mod
from ecdsa.util import bit_length, string_to_number


# --------------------------------------------------------------------
# Tunable parameters.  Every one of them is printed in the report, so a
# run is reproducible from its own output.
# --------------------------------------------------------------------

# Curves to probe, by ``ecdsa.curves.Curve.name``.  NIST256p is the
# curve the advisory names.  BRAINPOOLP256r1 is kept because its
# generator order sits far enough below 2**256 that the leak was
# measurable on it at a much lower observation count than on NIST256p.
# SECP160r1 is a useful third entry -- its order is barely above 2**160,
# so the old bit-length padding was cancelled for all but a vanishing
# fraction of nonces, fewer than one in 10**23 -- but it is left out of
# the default set to keep the runtime modest.
CURVE_NAMES = ["NIST256p", "BRAINPOOLP256r1"]

# Mode 2: number of timed signatures collected per curve.  The external
# harness defaults to 100000; 20000 is the point at which the leak was
# already statistically visible on BRAINPOOLP256r1 locally.
REPEAT = 20000

# Mode 1: nonces per bit-width bucket, and repetitions per nonce.  The
# reported observation is the minimum of the repetitions, which is the
# usual way to push scheduler noise out of a small sample.
CONTROLLED_PER_BUCKET = 80
MIN_OF = 5

# How many bits to drop below the order's bit length for each Mode 1
# bucket.  A width that would leave fewer than MIN_NONCE_BITS bits, or
# that no valid nonce can have, is named in the report as one this curve
# cannot supply rather than forced -- and rather than dropped in silence,
# which would leave the parameters naming more buckets than were timed.
CONTROLLED_BIT_DROPS = [0, 1, 4, 8, 32, 64, 128, 192]
MIN_NONCE_BITS = 8

# Bootstrap: resample count, the cap on paired rows used (a prefix of
# the pairs, so the choice is deterministic and cheap), and the sample
# count at or below which the external harness refuses to bootstrap.
BOOTSTRAP_RESAMPLES = 1000
BOOTSTRAP_MAX_PAIRS = 2000
BOOTSTRAP_MIN_SAMPLES = 50

# The two quantiles of the resample statistics that an interval is read
# at: a 95 % percentile interval, the level the external harness fixes
# and reports (``np.quantile(results, [0.025, 0.975])``).  Not a tunable
# -- the level is fixed there and here, which is why these intervals are
# descriptive evidence and take no part in the corrected-alpha decision.
# Named rather than written into the two calls that use them so that the
# level the endpoints are taken at and the level the note claims cannot
# drift apart, and so the self check has one place to compare against.
BOOTSTRAP_QUANTILES = (0.025, 0.975)

# Trimming proportions for the two bootstrapped location estimators,
# matching the external harness's ``trim_mean_05`` and ``trim_mean_45``.
# 0.45 from each tail is a near-median estimator.
TRIM_PROPORTIONS = [0.05, 0.45]

# The sign test needs more than this many paired rows to be reported at
# all, again following the external harness.
SIGN_TEST_MIN_PAIRS = 10

# Above this many paired rows the two-sided binomial p-value stops
# summing binomial coefficients in exact integer arithmetic and takes
# the same tail from the regularised incomplete beta function instead.
# Both are accurate at the corrected alpha this script decides against;
# the switch is a matter of cost, not of accuracy, and which one was
# used is printed per row.
EXACT_BINOM_MAX_N = 1000

# Significance level before correction; the external harness default.
ALPHA = 1e-6

# Sample counts at which the battery is re-run over a prefix of the
# Mode 2 observations, to find the smallest N that still detects.
PREFIX_SIZES = [500, 1000, 2000, 5000, 10000, 20000]

# A Mode 2 bucket needs this many observations before it is tested, and
# before it counts towards the monotone trend.  Mode 2 bucket sizes are
# dictated by chance: without a floor, a bucket holding three
# observations has a median that wanders by tens of microseconds on its
# own and would set the reported trend single-handedly.  Buckets below
# the floor are named in the report rather than dropped silently.
MIN_BUCKET_SAMPLES = 32

# The same floor for Mode 1, where the bucket size is chosen rather than
# drawn, so lowering CONTROLLED_PER_BUCKET for a quick run shrinks the
# samples instead of silently switching the whole battery off.
CONTROLLED_MIN_SAMPLES = min(MIN_BUCKET_SAMPLES, CONTROLLED_PER_BUCKET)

# At most this many buckets (largest bit lengths first) are tested, so
# that the Bonferroni divisor stays meaningful instead of being driven
# by a long tail of buckets holding a handful of samples each.
MAX_TESTED_BUCKETS = 8

# Mode 2 pairs every observation with an observation from the reference
# bucket taken within this many SIGNING ATTEMPTS of it, and refuses the
# pair when there is none.  The bound is what makes the paired tests
# legitimate: two observations taken far apart differ by however much
# the machine drifted in between, and a paired test cannot tell that
# from an effect of the nonce.  Signing attempts rather than list
# positions because a dropped observation makes the two diverge -- see
# matched_differences, which also records why reuse of a reference
# observation had to be ruled out.
MAX_PAIR_GAP = 16

# Seed for nonce selection, digest selection and bootstrap resampling.
# The timings themselves are of course not reproducible.  Neither is one
# other value, and it is named here rather than left to be discovered:
# `ecdsa.ecdsa.Private_key.sign` draws a factor to blind its modular
# inversion with, from `os.urandom` and not from the ``entropy=``
# callable a caller can pass, so that draw differs between two runs of
# this script even in Mode 1, where the nonce and the digest are both
# fixed.  It takes no part in anything this script reports -- the
# signature it produces is the same either way -- and reaches the report
# only through the run time, which is not reproducible in any case.
# Everything else about a run is.
SEED = 12345

# Bound on retries when a signature is refused for a reason a fresh
# draw cures, which is an r or an s of exactly zero and nothing else --
# ``SIGN_RETRY``.  Exhausting the bound drops that observation and is
# counted, never raised.  A refusal a fresh draw does not cure, an
# entropy source that declines a draw among them, is ``SIGN_FATAL``, is
# never retried, and stops the collection it was part of.
MAX_SIGN_RETRIES = 8

# Observation counts published elsewhere for the same measurement, so a
# result can be placed on a scale without leaving this output.
CALIBRATION_ANCHORS = [
    (
        20000,
        "this instrument, BRAINPOOLP256r1, before any hardening "
        "(adjacent-bucket |z| about 4.7)",
    ),
    (
        719882,
        "the observation count in the upstream python-ecdsa report "
        "behind CVE-2024-23342",
    ),
    (
        43190069,
        "GnuTLS, after hardening compiled C, to see a residual step "
        "of about 34 ns (CVE-2024-28834, fixed in 3.8.4)",
    ),
]

# Mode 1 medians recorded on NIST256p before any hardening, at these
# same settings (80 nonces per bucket, minimum of 5), in microseconds.
# Printed beside the measured column purely as a reference point; the
# absolute values belong to the machine they were taken on, the shape
# of the column is what carries meaning.
REFERENCE_MEDIANS_NIST256P = {
    256: 483.3,
    255: 480.0,
    252: 469.0,
    248: 472.1,
    224: 421.6,
    192: 361.2,
    128: 244.3,
    64: 131.9,
}

# Asymptotic standard error of a sample median is this factor times the
# standard error of the mean, for a locally normal distribution.  Used
# only to put a scale on the difference between two bucket medians.
MEDIAN_SE_FACTOR = 1.2533

CLOCK = timeit.default_timer


# --------------------------------------------------------------------
# The bounds a comparison is judged under, gathered into one value.
#
# Four of the tunables above are not merely printed: they decide what
# the analysis functions below are allowed to compare, and therefore
# what those functions answer.  They are passed rather than read out of
# module state so that the self check can exercise those functions
# under bounds of its OWN, fixed once here.  Retuning a measurement
# constant for a run then changes the measurement, which is the point of
# a tunable, without changing what the self check measures -- a coupling
# that used to report a retuned constant as "a decision path of the
# report is wrong", blaming the report for the configuration.
#
# This is the same reasoning `CHECK_PAIRS` already applied to
# ``MIN_BUCKET_SAMPLES``, extended to the rest.
# --------------------------------------------------------------------


def measurement_limits(gap, most, sizes, alpha):
    """Bundle the four bounds an analysis is carried out under.

    *gap* is how many signing attempts apart two observations may be and
    still form a pair, *most* the greatest number of buckets that may be
    compared against the reference, *sizes* the prefix ladder the
    smallest-N scan walks, and *alpha* the significance level the
    Bonferroni correction divides.
    """
    return {"gap": gap, "most": most, "sizes": sizes, "alpha": alpha}


# The live configuration, built once.  Nothing writes to it.
LIMITS = measurement_limits(
    MAX_PAIR_GAP, MAX_TESTED_BUCKETS, PREFIX_SIZES, ALPHA
)


# --------------------------------------------------------------------
# Validity of the report, and the exit status that follows from it.
#
# A run that measured nothing, or measured something it cannot vouch
# for, has to be distinguishable from one that looked and found nothing
# -- by a caller reading only the exit code.  Detecting a dependence, or
# failing to, is deliberately NOT what sets the status: the "before" half
# of a before/after comparison has to be collectable too, so a complete
# report exits ``EXIT_REPORTED`` either way.  The external harness spends
# its exit code 1 on detection instead; this script leaves 1 to the
# self-check, which runs before any measurement.
#
# Every reason a run is not trustworthy is collected rather than raised,
# so that one unusable curve still prints its diagnostics and the reader
# sees the whole picture before the status.
# --------------------------------------------------------------------

EXIT_REPORTED = 0
EXIT_UNAVAILABLE = 2

PROBLEMS = []

# One entry per measurement this run was asked for, saying whether it
# actually carried out a statistical comparison.  Kept alongside
# ``PROBLEMS`` rather than folded into it because the two answer
# different questions: a problem is a reason a number cannot be
# trusted, while this is the record of whether there is a number at
# all.  The validity section reads both, and neither is inferred from
# the other -- a mode that compared nothing must not be able to reach
# ``EXIT_REPORTED`` merely because nothing else went wrong.
EVIDENCE = []


def note_problem(scope, description):
    """Record a reason the report is not usable as evidence.

    *scope* names what was being measured -- a curve, or a curve and a
    mode -- and *description* says what went wrong in the terms a reader
    needs in order to act on it.  Recording neither prints nor raises:
    the run continues, the closing validity section names every problem
    that was recorded, and the exit status follows from whether any were.
    """
    PROBLEMS.append((scope, description))


def note_evidence(scope, produced):
    """Record whether *scope* carried out a statistical comparison.

    Called exactly once per measurement the run was asked for, on every
    path out of it -- including the paths that give up early -- so that
    the count of comparisons asked for and the count produced are both
    facts rather than assumptions.

    "Every path out of it" includes the paths that never enter
    `probe_curve()` at all: a requested curve that is not registered, and
    a requested Edwards curve, are still two measurements this run was
    asked for, and `note_skipped_curve()` registers both of their modes
    as unproduced.  Leaving them out did not change any verdict -- each
    records a problem, so the status is withheld either way -- but it let
    the validity section say "2 of the 2 comparisons this run was asked
    for" in a run that had asked for six, which is the one sentence in
    the report a reader is entitled to take literally.
    """
    EVIDENCE.append((scope, produced))


# The two modes every curve this probe is given is asked for: injected
# nonces of a known width, and nonces the library drew that the probe
# recovers.  Enumerated as data so that the count of measurements a run
# is asked for follows from the code rather than from a comment, and so
# a curve skipped before either mode runs can still be accounted for in
# both.
CURVE_MODES = [1, 2]

# The one spelling of a mode's scope, kept in one place because three
# things have to agree on it: the two measurements register their
# evidence under it, the run loop registers the same two scopes as
# unproduced for a curve it cannot measure at all, and
# `problem_covers()` recognises the curve a mode belongs to by
# splitting the separator back off.
MODE_SEPARATOR = " mode "


def mode_scope(name, mode):
    """The evidence and problem scope of one mode of one curve.

    Every scope string in the report comes from here.  They used to be
    spelled out at each site, and a scope that is spelled differently in
    two places is two scopes: the tally counts one measurement twice and
    `note_missing_evidence()` reports a problem against a name no other
    part of the report uses.
    """
    return "%s%s%d" % (name, MODE_SEPARATOR, mode)


def curve_mode_scopes(name):
    """Every scope the run is asked for on the curve called *name*."""
    scopes = []
    for mode in CURVE_MODES:
        scopes.append(mode_scope(name, mode))
    return scopes


def unproduced_scopes(name):
    """Both of *name*'s mode scopes, in the order they are registered.

    Split out from `note_unproduced()` so the naming and the count can
    be pinned without appending to the live registry, which the self
    check must not do: it runs before the measurement loop, and an
    invented record there would be counted as a measurement this run was
    asked for.
    """
    return curve_mode_scopes(name)


def note_unproduced(name):
    """Register both of *name*'s measurements as having produced nothing.

    Called on the paths that never reach a measurement at all -- a name
    no curve answers to, a curve whose signing path this script cannot
    time -- so that the count of comparisons the run was asked for
    counts them.  Without it a run whose entire curve list was
    unmeasurable reported "0 of 0", which reads as a run that was asked
    for nothing rather than one that was asked for something and
    produced none of it.  The distinction is the whole point of the
    tally: the first is a configuration that requested no evidence, the
    second is a configuration that requested evidence and got none, and
    only the second is a reason to go and look at the curve list.
    """
    for scope in unproduced_scopes(name):
        note_evidence(scope, False)


# The verdict states that are NOT results, in either mode: no
# comparison produced a p-value (``insufficient``), or one produced a
# value that could not be read (``unavailable`` from
# `detection_state()`, ``invalid`` from `scan_headline()`).  Every other
# state -- a detection, a nondetection, a smallest-N -- rests on a
# comparison that was actually carried out.
NON_RESULT_STATES = ["insufficient", "unavailable", "invalid"]


def state_is_comparison(state):
    """Whether a printed verdict *state* rests on a real comparison.

    One predicate for both modes, so that the condition the exit status
    turns on is written once: `detection_state()` and `scan_headline()`
    disagree only on the spelling of the unreadable state, and
    `scan_headline()` may answer with a prefix size rather than a word,
    which is a result like any other.
    """
    for word in NON_RESULT_STATES:
        if state == word:
            return False
    return True


def evidence_tally(records):
    """``(produced, asked)`` over evidence *records*.

    A pure function of its argument so that the decision it feeds can be
    exercised against synthetic registries in the self check, without
    reaching into module state or having to stage a measurement.
    """
    produced = 0
    for _, carried in records:
        if carried:
            produced += 1
    return (produced, len(records))


def missing_evidence(records):
    """The scopes in *records* that produced no comparison, in order."""
    scopes = []
    for scope, carried in records:
        if not carried:
            scopes.append(scope)
    return scopes


def problem_covers(existing, scope):
    """Whether a problem recorded under *existing* explains *scope*.

    True for the scope itself, and for a mode of a curve whose problem
    was recorded against that curve as a whole.  A name no curve is
    registered under, or a curve with no ``sign_digest()`` path to time,
    is one fact about both of that curve's modes; repeating it once per
    mode would bury the single line that says which name to correct
    under two restatements of a consequence the reader has already been
    given the cause of.

    Pure, so the self check can pin the boundary directly: the separator
    has to follow *existing* immediately, which is what keeps one
    curve's problem from reaching another curve whose name it happens to
    begin with, and keeps a refused setting from reaching a mode at all.
    """
    if existing == scope:
        return True
    return scope.startswith(existing + MODE_SEPARATOR)


def unexplained_scopes(problems, records):
    """Scopes in *records* that produced nothing and *problems* omits.

    The pure half of `note_missing_evidence()`: which measurements need a
    problem of their own recorded for them, given what has been recorded
    already.  Pinning this directly is the only way to exercise the
    interaction between the two registries in the self check, since the
    recording half writes to module state the run itself depends on.
    """
    scopes = []
    for scope in missing_evidence(records):
        explained = False
        for existing, _ in problems:
            if problem_covers(existing, scope):
                explained = True
                break
        if not explained:
            scopes.append(scope)
    return scopes


def evidence_complete(records):
    """Whether every measurement in *records* produced a comparison.

    False for an EMPTY registry as well, which is the case that matters
    most: a run whose curve list was rejected, or which fell through the
    measurement loop without asking for anything, has produced no
    evidence at all, and "no measurement failed" is not the same claim
    as "every measurement succeeded".
    """
    produced, asked = evidence_tally(records)
    return asked > 0 and produced == asked


def report_status(problems, records):
    """The exit status *problems* and evidence *records* together imply.

    ``EXIT_REPORTED`` only when nothing was recorded against the run AND
    every measurement it was asked for carried out a comparison.  Both
    conditions are needed, and the second is the one this instrument
    learned the hard way: a mode can reach the end of its report having
    compared nothing at all -- every bucket below the testable floor,
    say -- and that state prints as "insufficient evidence" throughout
    the report while leaving no problem behind it.  Reading the status
    off the problem list alone therefore told a caller that a run which
    measured nothing was usable as evidence, which is the one thing the
    status exists to prevent.

    Pure, for the same reason `evidence_tally()` is: the self check pins
    this table of outcomes directly.
    """
    if problems:
        return EXIT_UNAVAILABLE
    if not evidence_complete(records):
        return EXIT_UNAVAILABLE
    return EXIT_REPORTED


# --------------------------------------------------------------------
# What a setting has to BE before it can be checked against a bound.
#
# The tables below compare tunables against bounds, and a comparison is
# only meaningful once the value on the left is a number.  On the newest
# interpreters ``0.0 < "1e-6"`` raises rather than answering, so a
# constant edited to a string -- a plausible slip, since every one of
# them appears as text in the report -- would end the run with a
# traceback out of the middle of a measurement instead of being NAMED as
# the constant to put back.
#
# The type tuples are taken from VALUES rather than from names on
# purpose.  ``long`` is a distinct type on the oldest interpreter this
# package supports and does not exist on the newest, and the ``u""``
# literal that would name the other text type does not parse on some of
# the ones in between; ``2**64`` and ``b"".decode()`` evaluate to the
# right type on every one of them.
# --------------------------------------------------------------------

INTEGER_TYPES = (type(0), type(2**64))
REAL_TYPES = (float,) + INTEGER_TYPES
STRING_TYPES = (type(""), type(b"".decode("ascii")))


def is_whole(value):
    """Whether *value* is a whole number this script can count with."""
    return isinstance(value, INTEGER_TYPES)


def is_real(value):
    """Whether *value* is a real number this script can compare."""
    return isinstance(value, REAL_TYPES)


def is_sequence(value):
    """Whether *value* is a list or tuple of settings entries.

    A string is deliberately not one, even though it iterates: a curve
    list edited from ``["NIST256p"]`` to ``"NIST256p"`` would otherwise
    pass as a sequence of eight one-character curve names.
    """
    return isinstance(value, (list, tuple))


def setting_complaint(name, requirement, value):
    """One complaint, naming the constant, its requirement and its value.

    Every complaint in this file has that shape, because a reader acts
    on one by editing a named constant: the name and what it currently
    holds both belong in the sentence.
    """
    return "%s has to be %s; it holds %r" % (name, requirement, value)


def setting_problems(alpha, gap, most, floor):
    """The settings above under which no verdict could be READ.

    Returns ``(constant, complaint)`` pairs, empty when the run may
    proceed.  Each complaint NAMES the constant it came from, which is
    the whole purpose: a retuned constant that leaves the report unable
    to say anything has to be reported as a retuned constant, not as a
    measurement that mysteriously found nothing, and not as a decision
    path of the report being wrong.

    Only settings that make a verdict unreadable are listed, and each is
    one where the answer is fixed before any signature is timed:

    * an *alpha* outside the open unit interval is not a significance
      level.  At zero no p-value can ever fall below the corrected
      threshold, so "not detected" is guaranteed however large a
      dependence is; at one or above every comparison rejects, so
      "detected" is guaranteed however flat the timing is.  Either way
      the printed verdict is a property of the setting rather than of
      the measurement.
    * a proximity bound below one attempt refuses every pair, so every
      bucket declines and there is nothing to compare.
    * a bucket cap below one compares no bucket against the reference,
      with the same result.
    * a sign-test floor below one lets that test report from a single
      pair, where its two-sided p-value is 1.0 by construction -- a
      number that is not a test result.

    A value that is not a number of the right kind is named by the same
    row as a value out of range, and for the same reason: the edit a
    reader has to make is the same one either way.  Checking the type
    first is what makes this function total, so that a mistyped constant
    reaches the reader as a named constant rather than as a comparison
    that raised.

    Deliberately NOT listed: an empty ``PREFIX_SIZES``.  Dropping the
    intermediate rungs is a legitimate edit, since the scan always adds
    the full sample as its last rung, so the smallest-N bound is simply
    coarser.  A setting that costs detail is not a setting that makes
    the report unreadable.

    Pure and parameterised so the self check can exercise the table
    without retuning the module.
    """
    complaints = []
    if not is_real(alpha) or not (0.0 < alpha < 1.0):
        complaints.append(
            (
                "ALPHA",
                "a significance level has to lie strictly between 0 and 1;"
                " %r makes the verdict a property of the setting rather"
                " than of the measurement" % (alpha,),
            )
        )
    if not is_whole(gap) or gap < 1:
        complaints.append(
            (
                "MAX_PAIR_GAP",
                "two observations have to be allowed at least one"
                " attempt apart to pair at all; %r refuses every pair,"
                " so no comparison could be carried out" % (gap,),
            )
        )
    if not is_whole(most) or most < 1:
        complaints.append(
            (
                "MAX_TESTED_BUCKETS",
                "at least one bucket has to be comparable against the"
                " reference; %r compares none, so no comparison could be"
                " carried out" % (most,),
            )
        )
    if not is_whole(floor) or floor < 1:
        complaints.append(
            (
                "SIGN_TEST_MIN_PAIRS",
                "the sign test needs more than one non-zero pair for its"
                " p-value to be able to fall below 1; %r lets it report"
                " from a single pair, where the value is 1.0 by"
                " construction" % (floor,),
            )
        )
    return complaints


# --------------------------------------------------------------------
# The settings a COLLECTION or an ESTIMATOR could not be carried out
# with, as distinct from the four above that decide a VERDICT.
#
# `setting_problems()` covers the settings under which the report's
# conclusion would be a property of the configuration rather than of the
# signing path.  These are the rest: the constants deciding what is
# collected, how much of it, and which estimator is computed from it.  A
# wrong value here does not bend a verdict, it produces evidence that is
# not evidence -- a bucket nothing was timed into, an interval resampled
# from fewer pairs than the interval's own floor admits, a "prefix" that
# is really the sample with its tail cut off -- and every one of those
# printed as though it were a measurement.
#
# Held as tables rather than as a run of hand-written branches so that
# the order complaints come out in is fixed, which is what lets the self
# check pin WHICH constants a given set of settings names.
# --------------------------------------------------------------------

# ``(name, requirement)`` for every count that has to be at least one.
# The requirement completes "<name> has to be ..." and says what breaks
# below the bound rather than restating the bound.
POSITIVE_COUNTS = [
    (
        "REPEAT",
        "a whole number of at least one, since it is how many"
        " signatures Mode 2 times and a run of none has no sample",
    ),
    (
        "CONTROLLED_PER_BUCKET",
        "a whole number of at least one, since it is how many nonces"
        " Mode 1 times per bucket and a run of none populates no bucket",
    ),
    (
        "MIN_OF",
        "a whole number of at least one, since a reported observation is"
        " the fastest of that many repetitions over the same nonce",
    ),
    (
        "MIN_NONCE_BITS",
        "a whole number of at least one, since it is the narrowest nonce"
        " width Mode 1 will time and no nonce has no significant bits",
    ),
    (
        "MIN_BUCKET_SAMPLES",
        "a whole number of at least one, since it is how many"
        " observations a Mode 2 bucket needs before it is compared and an"
        " empty bucket has no median to compare",
    ),
    (
        "CONTROLLED_MIN_SAMPLES",
        "a whole number of at least one, for the same reason"
        " MIN_BUCKET_SAMPLES is: it is that floor for Mode 1",
    ),
    (
        "BOOTSTRAP_RESAMPLES",
        "a whole number of at least one, since an interval is the"
        " quantiles of that many resample statistics and no resample"
        " leaves the row reading as tested with no interval in it",
    ),
    (
        "BOOTSTRAP_MAX_PAIRS",
        "a whole number of at least one, since it caps how many pairs an"
        " interval is resampled from",
    ),
    (
        "CLOCK_READS",
        "a whole number of at least one, since the timer granularity is"
        " the smallest gap between consecutive readings and no reading"
        " finds no gap",
    ),
    (
        "WARM_UP_ROUNDS",
        "a whole number of at least one, since the generator's"
        " multiplication table is built lazily on its first use: without"
        " a discarded signature first, the opening sample of every"
        " collection pays for the whole table",
    ),
    (
        "MAX_SIGN_RETRIES",
        "a whole number of at least one, since Mode 2 signs INSIDE the"
        " retry loop this bounds -- a bound of none signs nothing at all"
        " and drops every attempt",
    ),
]

# The same, for the two counts a run may legitimately set to none.
NON_NEGATIVE_COUNTS = [
    (
        "BOOTSTRAP_MIN_SAMPLES",
        "a whole number of none or more, since it is the pair count at"
        " or below which an interval is refused",
    ),
    (
        "EXACT_BINOM_MAX_N",
        "a whole number of none or more, since it is the pair count"
        " above which the binomial tail is taken from the beta function"
        " rather than summed exactly; none simply takes the beta form"
        " throughout",
    ),
]


def count_problems(settings, table, least):
    """The rows of *table* whose value in *settings* is not a count.

    One loop serves both count tables, so the complaint sentence is
    written once: *least* is the smallest value the table's rows admit.
    """
    complaints = []
    for name, requirement in table:
        value = settings[name]
        if not is_whole(value) or value < least:
            complaints.append(
                (name, setting_complaint(name, requirement, value))
            )
    return complaints


def every_count(values, least):
    """Whether every entry of *values* is a whole number, at or above
    *least*.

    A *least* of ``None`` drops the bound and asks only that the entries
    are whole numbers, which is what ``CONTROLLED_BIT_DROPS`` needs: a
    NEGATIVE drop asks for a width above the generator order's own, and
    that is a width the report legitimately names as one no nonce can
    have rather than a mistake to refuse.
    """
    for value in values:
        if not is_whole(value):
            return False
        if least is not None and value < least:
            return False
    return True


def every_trim(values):
    """Whether every entry of *values* is a usable trim proportion.

    A trim is the fraction cut from EACH tail, so it has to be at least
    none and strictly below one half.  At one half and above the two
    cuts meet and `trimmed_mean_sorted()` answers with the median, which
    is a defined statistic but not the trimmed mean the row is labelled
    with -- so an interval would be reported under a label it does not
    answer to, in the one column of this report that is read as evidence
    of a difference.
    """
    for value in values:
        if not is_real(value):
            return False
        if not (0.0 <= value < 0.5):
            return False
    return True


def every_curve_name(values):
    """Whether every entry of *values* could name a registered curve.

    A non-empty string could; anything else could not, and would reach
    the report as "no curve is registered under that name" against a
    value that was never a name -- true, but it names the wrong thing to
    go and fix.
    """
    for value in values:
        if not isinstance(value, STRING_TYPES) or not value:
            return False
    return True


def list_problems(settings):
    """The list-valued settings whose contents a run could not use.

    Three of the four may legitimately be EMPTY and are checked for
    their contents only.  An empty ``PREFIX_SIZES`` costs the
    intermediate rungs of the smallest-N scan and nothing else; an empty
    ``CONTROLLED_BIT_DROPS`` leaves Mode 1 with no bucket, which the
    report already names as insufficient evidence while Mode 2 still
    runs; and an empty ``CURVE_NAMES`` is answered by the run itself,
    which says so and withholds the status.  Refusing any of the three
    up front would trade a graceful, informative degradation for a stop.
    ``TRIM_PROPORTIONS`` is the exception: with no proportion in it the
    bootstrap resamples nothing and reports no interval at all, while
    the row still reads as one that was tested.
    """
    complaints = []
    trims = settings["TRIM_PROPORTIONS"]
    if not is_sequence(trims) or not trims or not every_trim(trims):
        complaints.append(
            (
                "TRIM_PROPORTIONS",
                setting_complaint(
                    "TRIM_PROPORTIONS",
                    "a non-empty list of proportions, each at least none"
                    " and strictly below one half, since each is the"
                    " fraction cut from EACH tail of a resample",
                    trims,
                ),
            )
        )
    sizes = settings["PREFIX_SIZES"]
    if not is_sequence(sizes) or not every_count(sizes, 1):
        complaints.append(
            (
                "PREFIX_SIZES",
                setting_complaint(
                    "PREFIX_SIZES",
                    "a list of whole sample counts of at least one each,"
                    " since a rung of none or fewer is not a prefix of"
                    " the observations -- a negative one slices the"
                    " sample's TAIL off instead and would be reported as"
                    " a negative N",
                    sizes,
                ),
            )
        )
    drops = settings["CONTROLLED_BIT_DROPS"]
    if not is_sequence(drops) or not every_count(drops, None):
        complaints.append(
            (
                "CONTROLLED_BIT_DROPS",
                setting_complaint(
                    "CONTROLLED_BIT_DROPS",
                    "a list of whole numbers of bits to drop below the"
                    " generator order's own width, since each is"
                    " subtracted from that width to name a bucket",
                    drops,
                ),
            )
        )
    names = settings["CURVE_NAMES"]
    if not is_sequence(names) or not every_curve_name(names):
        complaints.append(
            (
                "CURVE_NAMES",
                setting_complaint(
                    "CURVE_NAMES",
                    "a list of non-empty curve names, each as it is"
                    " spelled in ecdsa.curves",
                    names,
                ),
            )
        )
    return complaints


def both_usable(named, first, second):
    """Whether neither *first* nor *second* is already in *named*."""
    return first not in named and second not in named


def coherence_problems(settings, named):
    """Settings each usable on its own that cannot be used TOGETHER.

    *named* is the constants already complained about, and a pair with
    one of those in it is skipped: those values have not been
    established as numbers, so comparing them could raise, and the edit
    a reader has to make is on the list already.
    """
    complaints = []
    if both_usable(named, "BOOTSTRAP_MAX_PAIRS", "BOOTSTRAP_MIN_SAMPLES"):
        cap = settings["BOOTSTRAP_MAX_PAIRS"]
        floor = settings["BOOTSTRAP_MIN_SAMPLES"]
        if cap <= floor:
            complaints.append(
                (
                    "BOOTSTRAP_MAX_PAIRS",
                    "BOOTSTRAP_MAX_PAIRS caps an interval's sample at %r"
                    " pairs, which is not more than the %r"
                    " BOOTSTRAP_MIN_SAMPLES refuses to resample at or"
                    " below, so no interval could ever be reported"
                    % (cap, floor),
                )
            )
    if both_usable(named, "CONTROLLED_MIN_SAMPLES", "CONTROLLED_PER_BUCKET"):
        floor = settings["CONTROLLED_MIN_SAMPLES"]
        held = settings["CONTROLLED_PER_BUCKET"]
        if floor > held:
            complaints.append(
                (
                    "CONTROLLED_MIN_SAMPLES",
                    "CONTROLLED_MIN_SAMPLES asks a Mode 1 bucket for %r"
                    " observations before it is compared, but"
                    " CONTROLLED_PER_BUCKET times only %r into it, so no"
                    " bucket could ever be compared" % (floor, held),
                )
            )
    if both_usable(named, "MIN_BUCKET_SAMPLES", "REPEAT"):
        floor = settings["MIN_BUCKET_SAMPLES"]
        timed = settings["REPEAT"]
        if floor > timed:
            complaints.append(
                (
                    "MIN_BUCKET_SAMPLES",
                    "MIN_BUCKET_SAMPLES asks a Mode 2 bucket for %r"
                    " observations before it is compared, but REPEAT"
                    " times only %r signatures in total, so no bucket"
                    " could ever be compared" % (floor, timed),
                )
            )
    return complaints


def measurement_problems(settings):
    """Every setting in *settings* a measurement could not be made under.

    Returns ``(constant, complaint)`` pairs in the fixed order of the
    tables above, empty when the run may proceed.  Pure and
    parameterised for the same reason `setting_problems()` is: the self
    check exercises the whole table against synthetic settings without
    retuning the module.
    """
    complaints = count_problems(settings, POSITIVE_COUNTS, 1)
    complaints = complaints + count_problems(settings, NON_NEGATIVE_COUNTS, 0)
    seed = settings["SEED"]
    if not is_whole(seed):
        complaints.append(
            (
                "SEED",
                setting_complaint(
                    "SEED",
                    "a whole number, since every generator this script"
                    " seeds is seeded with it offset by an integer",
                    seed,
                ),
            )
        )
    factor = settings["MEDIAN_SE_FACTOR"]
    if not is_real(factor) or not factor > 0.0:
        complaints.append(
            (
                "MEDIAN_SE_FACTOR",
                setting_complaint(
                    "MEDIAN_SE_FACTOR",
                    "a real number above zero, since every bucket"
                    " standard error is that multiple of a standard"
                    " error of the mean and the span in standard errors"
                    " is divided by it",
                    factor,
                ),
            )
        )
    complaints = complaints + list_problems(settings)
    named = []
    for name, _ in complaints:
        named.append(name)
    return complaints + coherence_problems(settings, named)


def live_settings():
    """The execution-critical constants, by name, as one mapping.

    Gathered here so that `measurement_problems()` can be a pure
    function of its argument, which is what lets the self check exercise
    the whole table against synthetic settings without retuning the
    module -- the same separation `setting_problems()` already has, and
    for the same reason.  Read at call time, so the two constants
    defined further down the file are in it as well.
    """
    return {
        "REPEAT": REPEAT,
        "CONTROLLED_PER_BUCKET": CONTROLLED_PER_BUCKET,
        "MIN_OF": MIN_OF,
        "MIN_NONCE_BITS": MIN_NONCE_BITS,
        "MIN_BUCKET_SAMPLES": MIN_BUCKET_SAMPLES,
        "CONTROLLED_MIN_SAMPLES": CONTROLLED_MIN_SAMPLES,
        "BOOTSTRAP_RESAMPLES": BOOTSTRAP_RESAMPLES,
        "BOOTSTRAP_MAX_PAIRS": BOOTSTRAP_MAX_PAIRS,
        "BOOTSTRAP_MIN_SAMPLES": BOOTSTRAP_MIN_SAMPLES,
        "CLOCK_READS": CLOCK_READS,
        "WARM_UP_ROUNDS": WARM_UP_ROUNDS,
        "MAX_SIGN_RETRIES": MAX_SIGN_RETRIES,
        "EXACT_BINOM_MAX_N": EXACT_BINOM_MAX_N,
        "SEED": SEED,
        "MEDIAN_SE_FACTOR": MEDIAN_SE_FACTOR,
        "TRIM_PROPORTIONS": TRIM_PROPORTIONS,
        "PREFIX_SIZES": PREFIX_SIZES,
        "CONTROLLED_BIT_DROPS": CONTROLLED_BIT_DROPS,
        "CURVE_NAMES": CURVE_NAMES,
    }


def configuration_problems():
    """Every setting this run could not be carried out under.

    The verdict table first and the measurement table second, which is
    the order a reader meets the two kinds in: a setting that decides
    the conclusion before anything is timed, then one that decides
    whether there is anything to conclude from.
    """
    return setting_problems(
        ALPHA, MAX_PAIR_GAP, MAX_TESTED_BUCKETS, SIGN_TEST_MIN_PAIRS
    ) + measurement_problems(live_settings())


# --------------------------------------------------------------------
# Special functions.
#
# ``math.lgamma`` and ``math.erfc`` only arrived in Python 2.7, and this
# project still supports 2.6, so both have a fallback here.  On any
# interpreter that has the standard library version the ``getattr``
# bindings below select it and the fallbacks never run; they are kept
# because they are the only implementation available on the oldest
# interpreter the package declares support for.
# --------------------------------------------------------------------

_LOG_SQRT_2PI = 0.5 * math.log(2.0 * math.pi)
_SQRT_2 = math.sqrt(2.0)

# Lanczos coefficients, g = 7, n = 9; good to about 1e-15 relative for
# real arguments greater than zero.
_LANCZOS_G = 7.0
_LANCZOS_COEF = [
    0.99999999999980993,
    676.5203681218851,
    -1259.1392167224028,
    771.32342877765313,
    -176.61502916214059,
    12.507343278686905,
    -0.13857109526572012,
    9.9843695780195716e-6,
    1.5056327351493116e-7,
]


def lgamma_lanczos(x):
    """Natural log of the gamma function of a positive real *x*.

    Reflection below 0.5, Lanczos above it.  Present so that the
    Student's-t p-value can be computed on an interpreter that predates
    ``math.lgamma``.
    """
    if x <= 0.0:
        raise ValueError("lgamma_lanczos needs a positive argument")
    if x < 0.5:
        # gamma(x) * gamma(1 - x) == pi / sin(pi * x)
        return math.log(math.pi / math.sin(math.pi * x)) - lgamma_lanczos(
            1.0 - x
        )
    y = x - 1.0
    acc = _LANCZOS_COEF[0]
    for i in range(1, len(_LANCZOS_COEF)):
        acc += _LANCZOS_COEF[i] / (y + i)
    t = y + _LANCZOS_G + 0.5
    return _LOG_SQRT_2PI + (y + 0.5) * math.log(t) - t + math.log(acc)


# math.lgamma arrived in 2.7/3.2 and this package supports 2.6, so the
# library version is taken when present and the Lanczos approximation
# above stands in when it is not.  Written with getattr rather than a
# hasattr branch so that no interpreter ever evaluates a name it does
# not have, and so that a static version check reads the floor
# correctly.
log_gamma = getattr(math, "lgamma", lgamma_lanczos)


def _gamma_p_series(a, x):
    """Lower regularised incomplete gamma by its series; needs x < a+1."""
    if x <= 0.0:
        return 0.0
    term = 1.0 / a
    total = term
    ap = a
    for _ in range(1000):
        ap += 1.0
        term *= x / ap
        total += term
        if abs(term) < abs(total) * 1e-17:
            break
    return total * math.exp(-x + a * math.log(x) - log_gamma(a))


def _gamma_q_fraction(a, x):
    """Upper regularised incomplete gamma by continued fraction.

    Modified Lentz evaluation; intended for x >= a + 1, where the series
    above converges slowly.
    """
    tiny = 1e-300
    b = x + 1.0 - a
    c = 1.0 / tiny
    d = 1.0 / b
    h = d
    for i in range(1, 1000):
        an = -i * (i - a)
        b += 2.0
        d = an * d + b
        if abs(d) < tiny:
            d = tiny
        c = b + an / c
        if abs(c) < tiny:
            c = tiny
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < 1e-17:
            break
    return math.exp(-x + a * math.log(x) - log_gamma(a)) * h


def erfc_incomplete_gamma(x):
    """Complementary error function via the incomplete gamma integral.

    ``erfc(x) == Q(1/2, x**2)`` for non-negative *x*, and ``erfc(-x) ==
    2 - erfc(x)``.  Present so that a normal tail probability can be
    computed on an interpreter that predates ``math.erfc``, and accurate
    far enough into the tail to be compared against a corrected alpha.
    """
    z = abs(float(x))
    if z == 0.0:
        return 1.0
    zz = z * z
    if zz < 1.5:
        tail = 1.0 - _gamma_p_series(0.5, zz)
    else:
        tail = _gamma_q_fraction(0.5, zz)
    if tail < 0.0:
        tail = 0.0
    if x < 0.0:
        return 2.0 - tail
    return tail


# math.erfc arrived in 2.7/3.2 as well; same arrangement as log_gamma
# above, with the incomplete-gamma form standing in on 2.6.
erfc = getattr(math, "erfc", erfc_incomplete_gamma)


def normal_two_sided_p(z):
    """Two-sided tail probability of the standard normal at *z*."""
    return erfc(abs(z) / _SQRT_2)


def _beta_fraction(a, b, x):
    """Continued fraction of the incomplete beta function.

    Modified Lentz evaluation of the ``betacf`` recurrence; the caller
    is responsible for choosing the argument order that converges.
    """
    tiny = 1e-300
    qab = a + b
    qap = a + 1.0
    qam = a - 1.0
    c = 1.0
    d = 1.0 - qab * x / qap
    if abs(d) < tiny:
        d = tiny
    d = 1.0 / d
    h = d
    for m in range(1, 300):
        m2 = 2 * m
        aa = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1.0 + aa * d
        if abs(d) < tiny:
            d = tiny
        c = 1.0 + aa / c
        if abs(c) < tiny:
            c = tiny
        d = 1.0 / d
        h *= d * c
        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
        d = 1.0 + aa * d
        if abs(d) < tiny:
            d = tiny
        c = 1.0 + aa / c
        if abs(c) < tiny:
            c = tiny
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < 1e-16:
            break
    return h


def betainc(a, b, x):
    """Regularised incomplete beta function ``I_x(a, b)``."""
    if x <= 0.0:
        return 0.0
    if x >= 1.0:
        return 1.0
    front = math.exp(
        log_gamma(a + b)
        - log_gamma(a)
        - log_gamma(b)
        + a * math.log(x)
        + b * math.log1p(-x)
    )
    if x < (a + 1.0) / (a + b + 2.0):
        return front * _beta_fraction(a, b, x) / a
    return 1.0 - front * _beta_fraction(b, a, 1.0 - x) / b


def student_t_two_sided_p(t, df):
    """Two-sided p-value of Student's t statistic *t* on *df* degrees.

    ``P(|T| >= |t|) == I_{df/(df+t^2)}(df/2, 1/2)``, evaluated exactly
    rather than by a normal approximation, so the value is usable at
    small sample counts as well as large ones.
    """
    if df <= 0:
        return 1.0
    tt = float(t) * float(t)
    if tt != tt:
        return 1.0
    if tt == float("inf"):
        return 0.0
    return betainc(df / 2.0, 0.5, df / (df + tt))


# --------------------------------------------------------------------
# Numeric validity.
#
# A timing measurement that is not a finite number is not a small
# measurement, it is the absence of one -- and every statistic below
# turns one into something that reads like a result.  A NaN compares
# false against zero in both directions, so a sign test discards it as a
# tie; ranking a set holding one puts it wherever the sort happens to
# leave it; the mean and the standard deviation of the set come out NaN,
# and a two-sided Student's-t p-value answers a NaN statistic with
# exactly 1.0.  Measured on a set of twenty NaNs, the paired t test
# reported p = 1.0 and the Wilcoxon test p = 8.9e-05, and neither number
# is a statement about anything at all.
#
# Nothing that is not finite is therefore allowed past this point.  A
# sample holding one invalidates the comparison it belongs to, and an
# invalidated comparison is reported as unavailable -- never as an
# absence of a leak, which is the reading it would otherwise get.
# --------------------------------------------------------------------

# What every test says when it refuses a sample on these grounds.
NON_FINITE_NOTE = "sample holds a value that is not a finite number"


def is_finite(value):
    """Whether *value* reads as a finite floating point number.

    ``math.isnan`` and ``math.isinf`` both arrived in Python 2.6, the
    oldest interpreter this package supports, so no comparison trick is
    needed here.  Anything ``float()`` refuses is refused too -- notably
    the ``None`` a test carries when it declines to run -- which is what
    lets one predicate guard both a missing p-value and an unusable one.
    Only floats and ``None`` ever reach it; the conversion is duck typed
    rather than type checked so that a ``gmpy`` number would pass as
    readily as an ``int``.
    """
    try:
        number = float(value)
    except (TypeError, ValueError):
        return False
    return not (math.isnan(number) or math.isinf(number))


def all_finite(values):
    """Whether every element of *values* is a finite real number."""
    for value in values:
        if not is_finite(value):
            return False
    return True


# --------------------------------------------------------------------
# Descriptive statistics.
# --------------------------------------------------------------------


def mean(values):
    """Arithmetic mean; ``math.fsum`` keeps long samples honest."""
    if not values:
        return float("nan")
    return math.fsum(values) / len(values)


def sample_sd(values):
    """Sample standard deviation with Bessel's correction."""
    count = len(values)
    if count < 2:
        return 0.0
    avg = mean(values)
    total = math.fsum([(v - avg) * (v - avg) for v in values])
    return math.sqrt(total / (count - 1))


def median(values):
    """Median of *values*; the average of the middle pair when even."""
    if not values:
        return float("nan")
    ordered = sorted(values)
    count = len(ordered)
    half = count // 2
    if count % 2:
        return ordered[half]
    return (ordered[half - 1] + ordered[half]) / 2.0


def quantile_sorted(ordered, q):
    """Linear-interpolated quantile of an already sorted sequence.

    Matches the default ``numpy.quantile`` interpolation, which is what
    the external harness's bootstrap interval uses.
    """
    count = len(ordered)
    if count == 0:
        return float("nan")
    if count == 1:
        return ordered[0]
    pos = (count - 1) * q
    low = int(math.floor(pos))
    frac = pos - low
    if low + 1 >= count:
        return ordered[count - 1]
    return ordered[low] + frac * (ordered[low + 1] - ordered[low])


def is_trim_proportion(value):
    """Whether *value* is a trim a reported interval may be built on.

    A finite fraction of the sample, at or above zero and strictly below
    one half.  Both ends of that domain are load bearing, and so is the
    finiteness:

    * **below zero** the cut goes negative, and a negative cut turns the
      slice in `trimmed_mean_sorted()` into ``ordered[-cut:]`` -- the
      sample's UPPER TAIL, which is not empty, so the median fallback
      cannot catch it.  The largest few observations would come back as
      if they were a central estimate;
    * **at one half or above** an even sized sample is emptied outright,
      and `trimmed_mean_sorted()` then answers with the MEDIAN, which is
      a different estimator from the one an interval's ``trim`` column
      would name.  ``scipy.stats.trim_mean`` raises for the same input,
      and a bootstrap resample has the size of the sample it came from,
      so an even sample is not a corner case here;
    * **anything that is not a finite number** never reaches a
      comparison at all: ``int(count * value)`` raises for a ``nan`` or
      an infinity, and the middle of a measurement is the wrong place to
      discover that.

    The predicate is separate from the estimator on purpose.  The
    estimator stays total -- it answers something for every input, which
    is what keeps a resample from raising -- while this decides what
    `bootstrap_test()` is willing to PRINT a trim label against.
    """
    if not is_finite(value):
        return False
    return 0.0 <= value < 0.5


def trimmed_mean_sorted(ordered, proportion):
    """Mean of an already sorted sample, *proportion* cut from each tail.

    ``int(n * proportion)`` observations go from each end, which is the
    convention ``scipy.stats.trim_mean`` follows.  A proportion that
    would empty the sample falls back to the median, so the estimator is
    always defined.

    That fallback is why `is_trim_proportion()` exists and why
    `bootstrap_test()` refuses a proportion of one half or more before
    resampling: the value this function returns for such a proportion is
    a perfectly good number, it is simply the median rather than the
    trimmed mean the caller asked for, and an interval labelled with a
    trim it did not perform is worse than no interval.  The two
    contracts are complementary -- total here, selective there.

    A proportion below zero, and any proportion that is not a finite
    number, are refused outright rather than trimmed with.  The negative
    case would make ``cut`` negative, and a negative cut turns the slice
    below into ``ordered[-cut:]`` -- the sample's UPPER TAIL, which is
    not empty, so the median fallback cannot catch it.  The function
    would then return the largest observation, or the mean of the largest
    few, as if it were a trimmed mean, and the bootstrap built on it
    would report a confidence interval far from zero and mark it as
    excluding zero: a fabricated difference, in the one column of this
    report that is read as evidence of one.  The non-finite case would
    not return anything at all -- ``int(count * nan)`` raises
    ``ValueError`` and ``int(count * inf)`` raises ``OverflowError``.
    ``scipy.stats.trim_mean`` raises for the negative input; ``nan`` is
    this script's equivalent for both, because every caller already
    refuses a non-finite statistic and says so in the table rather than
    raising in the middle of a measurement.

    A proportion at one half or above is a different case and is
    deliberately NOT refused here.  It is not a fabrication: the two
    cuts meet, the core empties, and the median fallback below is then
    the only defined answer left -- which is a statistic, just not the
    trimmed mean a row labelled with that proportion answers to.  So it
    is refused where it would be REPORTED, by `bootstrap_test()`, which
    can name the constant it came from, and before anything is timed, by
    `every_trim()`.  This estimator stays total.

    Sorted input is a requirement rather than a convenience: the
    bootstrap sorts every resample anyway and would otherwise sort it a
    second time, and every trimmed mean in the report then comes from
    this one function instead of from two similar-looking copies.
    """
    count = len(ordered)
    if count == 0:
        return float("nan")
    if not is_finite(proportion) or proportion < 0.0:
        return float("nan")
    cut = int(count * proportion)
    core = ordered[cut : count - cut]
    if not core:
        return median(ordered)
    return math.fsum(core) / len(core)


def spearman_rho(xs, ys):
    """Spearman rank correlation of two equally long sequences.

    Used on the per-bucket table to put one number on "do the medians
    move monotonically with the nonce bit width".  Mid-ranks for ties;
    returns ``nan`` when either side has no spread at all.
    """
    count = len(xs)
    if count < 2 or count != len(ys):
        return float("nan")
    rx = mid_ranks(xs)
    ry = mid_ranks(ys)
    mx = mean(rx)
    my = mean(ry)
    cov = math.fsum([(rx[i] - mx) * (ry[i] - my) for i in range(count)])
    vx = math.fsum([(rx[i] - mx) ** 2 for i in range(count)])
    vy = math.fsum([(ry[i] - my) ** 2 for i in range(count)])
    if vx <= 0.0 or vy <= 0.0:
        return float("nan")
    return cov / math.sqrt(vx * vy)


def mid_ranks(values):
    """Ranks of *values*, ties sharing the average of their positions."""
    count = len(values)
    order = sorted(range(count), key=lambda i: values[i])
    ranks = [0.0] * count
    pos = 0
    while pos < count:
        end = pos
        while end + 1 < count and values[order[end + 1]] == values[order[pos]]:
            end += 1
        shared = (pos + end) / 2.0 + 1.0
        for j in range(pos, end + 1):
            ranks[order[j]] = shared
        pos = end + 1
    return ranks


def pooled_median_se(ref, test):
    """Standard error of the difference between two sample medians.

    Each side contributes ``MEDIAN_SE_FACTOR * sd / sqrt(n)``, the
    asymptotic standard error of a median for a locally normal
    distribution, and the two are combined in quadrature.  It is a scale
    for the difference, not a test; the tests are below.
    """
    if len(ref) < 2 or len(test) < 2:
        return float("nan")
    se_ref = MEDIAN_SE_FACTOR * sample_sd(ref) / math.sqrt(len(ref))
    se_test = MEDIAN_SE_FACTOR * sample_sd(test) / math.sqrt(len(test))
    return math.sqrt(se_ref * se_ref + se_test * se_test)


# --------------------------------------------------------------------
# The four tests, mirroring tlsfuzzer/analysis.py::analyze_bit_sizes:
# sign_test, paired_t_test, wilcoxon_test, bootstrap_test.
#
# Each takes the already paired differences and returns a dict whose
# "p" is None when the test declines to run, with "note" saying why.
# Nothing here raises on a degenerate sample.
# --------------------------------------------------------------------


def ratio_over_power_of_two(numerator, exponent):
    """``numerator / 2**exponent`` as a float.

    Written this way because ``float(numerator) / float(2 ** exponent)``
    raises ``OverflowError`` on the older interpreters this package
    supports as soon as the exponent passes 1024, and the exact binomial
    tail below reaches that easily.  Extracting the mantissa first and
    scaling with ``math.ldexp`` keeps full double precision and
    underflows to zero cleanly instead of raising.
    """
    if numerator <= 0:
        return 0.0
    shift = bit_length(numerator) - 53
    if shift < 0:
        shift = 0
    return math.ldexp(float(numerator >> shift), shift - exponent)


def binomial_two_sided_p(successes, trials):
    """Two-sided p-value of *successes* out of *trials* against p = 0.5.

    The distribution is symmetric at p = 0.5, so the two-sided
    probability is twice the lower tail at
    ``min(successes, trials - successes)``, capped at one.  That tail is
    computed two ways, and the choice between them is about cost alone:

    * while ``trials <= EXACT_BINOM_MAX_N``, by summing binomial
      coefficients in exact integer arithmetic;
    * above it, from the regularised incomplete beta function, through
      the identity ``P(X <= k) == I_{1/2}(n - k, k + 1)``.  The integer
      sum stays correct there but grows to thousands of bits per term,
      and at the sample counts this script reaches it costs milliseconds
      per call against microseconds for the beta form.

    A normal approximation with a continuity correction is deliberately
    NOT used, although it is the obvious cheap choice, because it is not
    accurate where this p-value is read.  The decision it feeds is taken
    against a Bonferroni-corrected alpha around 1e-7, and at
    ``trials = 1100, successes = 462`` the approximation gives
    1.3171e-07 where the true two-sided probability is 1.2415e-07 -- on
    the other side of the 1.25e-07 threshold a run of eight comparisons
    computes, so the approximation alone would have reported a detection
    that is not there.  The error grows without bound in the far tail:
    at ``successes = 0`` it is off by more than seventy orders of
    magnitude.

    The beta form was checked against the integer sum for every
    successes count at trials of 1001, 1100, 1500, 2000, 4096, 5000,
    10000 and 20000 -- some nine thousand comparisons.  Wherever the
    tail is a normal double it agrees to a relative error below 1e-10,
    worst measured 3.2e-11.  Below roughly 1e-308 the two differ by one
    or two units in the last place of the smallest representable double,
    which is a large relative error and an absolute difference of 5e-324;
    no threshold this script compares against can tell either value from
    zero.

    Returns ``(p, method)`` so the caller can print which was used.
    """
    if trials <= 0:
        return (1.0, "none")
    smaller = min(successes, trials - successes)
    if trials <= EXACT_BINOM_MAX_N:
        # sum of C(trials, i) for i in 0..smaller, exactly
        coefficient = 1
        total = 1
        for i in range(smaller):
            coefficient = coefficient * (trials - i) // (i + 1)
            total += coefficient
        probability = 2.0 * ratio_over_power_of_two(total, trials)
        if probability > 1.0:
            probability = 1.0
        return (probability, "exact")
    probability = 2.0 * betainc(trials - smaller, smaller + 1.0, 0.5)
    if probability > 1.0:
        probability = 1.0
    return (probability, "beta")


def sign_test(differences):
    """Sign test on paired *differences* against a median of zero.

    Zero differences carry no sign and are discarded, as the external
    harness's use of ``binomtest`` on the count of positive pairs does.
    Declines below ``SIGN_TEST_MIN_PAIRS + 1`` usable pairs, matching
    the harness's requirement of more than ten paired rows, and declines
    outright on a sample holding anything that is not finite -- such a
    value would be discarded as a tie here, silently, since it compares
    false against zero in both directions.
    """
    if not all_finite(differences):
        return {
            "p": None,
            "method": "none",
            "pairs": len(differences),
            "positive": 0,
            "note": NON_FINITE_NOTE,
        }
    positive = 0
    usable = 0
    for value in differences:
        if value > 0.0:
            positive += 1
            usable += 1
        elif value < 0.0:
            usable += 1
    if usable <= SIGN_TEST_MIN_PAIRS:
        return {
            "p": None,
            "method": "none",
            "pairs": usable,
            "positive": positive,
            "note": "needs more than %d non-zero pairs"
            % (SIGN_TEST_MIN_PAIRS,),
        }
    probability, method = binomial_two_sided_p(positive, usable)
    return {
        "p": probability,
        "method": method,
        "pairs": usable,
        "positive": positive,
        "note": "",
    }


def paired_t_test(differences):
    """Two-sided paired t-test on *differences* against a mean of zero.

    The p-value comes from the exact Student's-t distribution, not from
    a normal approximation, so it is meaningful at small sample counts.

    Declines on a sample holding anything that is not finite, and on a
    statistic that comes out that way: a NaN statistic is answered by the
    Student's-t tail with exactly 1.0, which reads as the strongest
    possible evidence of no difference and is nothing of the kind.
    """
    count = len(differences)
    if not all_finite(differences):
        return {
            "p": None,
            "t": float("nan"),
            "df": 0,
            "mean": float("nan"),
            "note": NON_FINITE_NOTE,
        }
    if count < 2:
        return {
            "p": None,
            "t": float("nan"),
            "df": 0,
            "mean": float("nan"),
            "note": "needs at least 2 pairs",
        }
    avg = mean(differences)
    spread = sample_sd(differences)
    if spread <= 0.0:
        # every pair identical: a difference of exactly zero is no
        # evidence at all, anything else is as strong as it gets
        return {
            "p": 1.0 if avg == 0.0 else 0.0,
            "t": float("nan"),
            "df": count - 1,
            "mean": avg,
            "note": "zero variance in the paired differences",
        }
    statistic = avg / (spread / math.sqrt(count))
    if not is_finite(statistic):
        return {
            "p": None,
            "t": statistic,
            "df": count - 1,
            "mean": avg,
            "note": "the t statistic is not a finite number",
        }
    return {
        "p": student_t_two_sided_p(statistic, count - 1),
        "t": statistic,
        "df": count - 1,
        "mean": avg,
        "note": "",
    }


def wilcoxon_test(differences):
    """Wilcoxon signed-rank test on paired *differences*.

    Zero differences are discarded, absolute differences are ranked with
    mid-ranks for ties, and the signed-rank sum is referred to a normal
    approximation carrying the standard tie correction.  The p-value is
    an approximation and is labelled as one wherever it is printed; no
    exact signed-rank distribution is computed here.

    Declines on a sample holding anything that is not finite.  Such a
    value survives the ``!= 0.0`` filter below, and where it then lands
    in the ranking is whatever the sort leaves it at, so the signed-rank
    sum it contributes to is a statistic of nothing.  This is the test
    that was measured returning p = 8.9e-05 on a sample of twenty NaNs.
    """
    if not all_finite(differences):
        return {
            "p": None,
            "z": float("nan"),
            "w_plus": float("nan"),
            "pairs": len(differences),
            "note": NON_FINITE_NOTE,
        }
    nonzero = [value for value in differences if value != 0.0]
    count = len(nonzero)
    if count < 2:
        return {
            "p": None,
            "z": float("nan"),
            "w_plus": float("nan"),
            "pairs": count,
            "note": "needs at least 2 non-zero pairs",
        }
    magnitudes = [abs(value) for value in nonzero]
    ranks = mid_ranks(magnitudes)
    w_plus = math.fsum([ranks[i] for i in range(count) if nonzero[i] > 0.0])
    expected = count * (count + 1) / 4.0
    variance = count * (count + 1) * (2 * count + 1) / 24.0
    # tie correction: subtract (t**3 - t) / 48 per group of equal ranks
    tie_total = 0.0
    ordered = sorted(magnitudes)
    pos = 0
    while pos < count:
        end = pos
        while end + 1 < count and ordered[end + 1] == ordered[pos]:
            end += 1
        size = end - pos + 1
        if size > 1:
            tie_total += (size * size * size - size) / 48.0
        pos = end + 1
    variance -= tie_total
    if variance <= 0.0:
        return {
            "p": None,
            "z": float("nan"),
            "w_plus": w_plus,
            "pairs": count,
            "note": "degenerate rank variance",
        }
    z = (w_plus - expected) / math.sqrt(variance)
    if not is_finite(z):
        return {
            "p": None,
            "z": z,
            "w_plus": w_plus,
            "pairs": count,
            "note": "the signed-rank statistic is not a finite number",
        }
    return {
        "p": normal_two_sided_p(z),
        "z": z,
        "w_plus": w_plus,
        "pairs": count,
        "note": "normal approximation, tie corrected",
    }


def bootstrap_test(
    differences, rnd, proportions=TRIM_PROPORTIONS, cap=BOOTSTRAP_MAX_PAIRS
):
    """Percentile bootstrap intervals on trimmed means of *differences*.

    One interval per entry in *proportions*, which is ``TRIM_PROPORTIONS``
    for every caller in the report and a parameter only so that the
    refusal below can be exercised against a fixed list.  Each is read
    at the two ``BOOTSTRAP_QUANTILES`` of ``BOOTSTRAP_RESAMPLES``
    resample statistics -- the same 95 % percentile interval the external
    harness reports, and the level the note below names.  The
    confidence level is fixed at 95 % there and here, so these intervals
    are descriptive evidence and are deliberately NOT used for the
    corrected-alpha detection decision; that rests on the three p-value
    tests above.

    Declines at or below ``BOOTSTRAP_MIN_SAMPLES`` pairs, as the harness
    does, and on a sample holding anything that is not finite.  At most
    *cap* pairs are used -- ``BOOTSTRAP_MAX_PAIRS`` for every caller in
    the report, a parameter for the same reason *proportions* is -- taken
    as a prefix so the choice consumes no randomness and stays identical
    between runs with the same seed.

    The floor is applied TWICE, once to the pairs available and once to
    what survives the cap, and both are needed.  Checking only the
    available count let a cap below the floor report an interval
    resampled from fewer pairs than the floor exists to forbid: the
    sample was large enough, the cap then threw most of it away, and the
    row said "95 % percentile interval" over what was left.  The second
    refusal names ``BOOTSTRAP_MAX_PAIRS``, because that is the constant
    to edit -- collecting more pairs cannot cure it.

    A trim proportion this script cannot trim with declines the row
    before any resampling, and the note names the constant it came from.
    Below zero the estimator itself refuses (see
    `trimmed_mean_sorted()`); at one half and above the estimator answers
    with the median, which is a statistic but not the one the row is
    labelled with, so the refusal has to live here.  Either way, saying
    it here means the report names WHICH tunable put the row out of
    action instead of leaving a reader to infer it from a row of dashes.

    A trim that `is_trim_proportion()` refuses declines the row before
    any resampling, and the note names the constant it came from and the
    domain it left.  All three ways out of that domain are refused here
    rather than left to the estimator, and each for a reason of its own:

    * a value that is not finite would raise out of ``int()`` in the
      middle of a resample loop, taking the whole measurement with it;
    * a negative value would come back as the sample's upper tail
      dressed as a central estimate (see `trimmed_mean_sorted()`);
    * a value of one half or more would come back as the MEDIAN under a
      ``trim`` label naming a trimmed mean that was never computed --
      the one failure of the three that produces a plausible looking
      interval, which is why it cannot be left to a finiteness guard.

    Refusing here rather than only in the estimator also means the report
    says WHICH tunable put the row out of action instead of leaving a
    reader to infer it from a row of dashes.
    """
    available = len(differences)
    if not all_finite(differences):
        return {
            "intervals": [],
            "used": available,
            "note": NON_FINITE_NOTE,
        }
    for proportion in proportions:
        if not is_trim_proportion(proportion):
            return {
                "intervals": [],
                "used": available,
                "note": "TRIM_PROPORTIONS holds %r, which is not a finite "
                "proportion below 0.5" % (proportion,),
            }
    if available <= BOOTSTRAP_MIN_SAMPLES:
        return {
            "intervals": [],
            "used": available,
            "note": "needs more than %d pairs" % (BOOTSTRAP_MIN_SAMPLES,),
        }
    sample = differences[:cap]
    size = len(sample)
    if size <= BOOTSTRAP_MIN_SAMPLES:
        return {
            "intervals": [],
            "used": size,
            "note": "BOOTSTRAP_MAX_PAIRS caps the sample at %d of the %d "
            "pairs available, which is not more than the %d needed"
            % (size, available, BOOTSTRAP_MIN_SAMPLES),
        }
    draw = rnd.randrange
    statistics = []
    for _ in proportions:
        statistics.append([])
    for _ in range(BOOTSTRAP_RESAMPLES):
        resample = [sample[draw(size)] for _ in range(size)]
        resample.sort()
        for index in range(len(proportions)):
            statistics[index].append(
                trimmed_mean_sorted(resample, proportions[index])
            )
    intervals = []
    for index in range(len(proportions)):
        ordered = sorted(statistics[index])
        low = quantile_sorted(ordered, BOOTSTRAP_QUANTILES[0])
        high = quantile_sorted(ordered, BOOTSTRAP_QUANTILES[1])
        if not is_finite(low) or not is_finite(high):
            # an endpoint that is not a finite number is not an interval;
            # reporting one whose "excludes zero" column was read off a
            # NaN comparison would be worse than reporting none
            return {
                "intervals": [],
                "used": size,
                "note": "an interval endpoint is not a finite number",
            }
        intervals.append(
            {
                "trim": proportions[index],
                "low": low,
                "high": high,
                "excludes_zero": low > 0.0 or high < 0.0,
            }
        )
    return {
        "intervals": intervals,
        "used": size,
        "note": "95%% percentile interval, %d resamples"
        % (BOOTSTRAP_RESAMPLES,),
    }


# --------------------------------------------------------------------
# Measurement primitives.
#
# Nothing below monkey-patches the library.  No attribute of any module
# in ``ecdsa`` is assigned to and no method is wrapped; the probe only
# calls documented entry points and reads ``ellipticcurve.GMPY`` for the
# report.  Those calls do have the side effects the library documents for
# them -- signing with a registered generator fills that generator's lazy
# multiplication table on first use, which is a cache the library manages
# itself -- and the warm-up below is there so the first timed signature
# is not the one that pays for it.  Point-operation counting, which does
# need instrumentation, belongs in the unit suite where the counts are
# exact.
# --------------------------------------------------------------------

CLOCK_READS = 20000


def measure_clock_resolution(reads):
    """Smallest non-zero gap between two consecutive clock readings."""
    previous = CLOCK()
    smallest = None
    for _ in range(reads):
        current = CLOCK()
        gap = current - previous
        previous = current
        if gap > 0.0 and (smallest is None or gap < smallest):
            smallest = gap
    if smallest is None:
        return float("nan")
    return smallest


def raw_signature(r, s, order):
    """``sigencode`` that hands back the two integers untouched.

    ``sign_digest()`` takes the encoder as a documented parameter, so
    this keeps a serialisation step out of the timed region and gives
    the nonce recovery the integers it needs without a decode.  The
    order is accepted and ignored, as the encoder contract requires.
    """
    del order
    return (r, s)


def random_bytes(rnd, length):
    """*length* bytes drawn from *rnd*, as a ``bytes`` object.

    Built through ``bytearray`` rather than ``int.to_bytes`` so that it
    works on every interpreter this package supports.
    """
    return bytes(bytearray([rnd.getrandbits(8) for _ in range(length)]))


def seeded_entropy(rnd):
    """An ``os.urandom``-shaped callable driven by *rnd*.

    ``util.randrange()`` takes an ``entropy=`` callable precisely so
    that a caller can make nonce selection repeatable, and
    ``sign_digest()`` forwards it.  Handing it a seeded source is what
    makes bucket membership identical between two runs of this script;
    the nonces are still drawn by the library, uniformly, through its
    own code path.  The timings are of course not repeatable.
    """

    def entropy(length):
        """*length* bytes, in the shape ``os.urandom`` returns them."""
        return random_bytes(rnd, length)

    return entropy


def nonce_of_bit_length(rnd, bits, order):
    """A uniform nonce with exactly *bits* significant bits.

    Drawn directly from ``[2**(bits-1), min(order, 2**bits))``, which is
    the same set as "set bit ``bits-1``, randomise the rest, reject
    anything not below the order" -- but built rather than rejected, so
    it terminates even where the rejected region dominates.  The top
    bucket of SECP160r1 is exactly that case: its order is barely above
    ``2**160``, so only about one in ``2**80`` of the 161-bit values is
    a valid nonce and rejection sampling would never finish.

    Returns ``None`` when no nonce of that width exists for the order.
    """
    low = 1 << (bits - 1)
    high = 1 << bits
    if high > order:
        high = order
    if high <= low:
        return None
    return low + rnd.randrange(high - low)


def width_is_supplyable(bits, order):
    """Whether a nonce of exactly *bits* significant bits exists below
    *order*.

    The same question `nonce_of_bit_length()` answers by returning
    ``None``, decided here without drawing and without a random source.
    Its interval is ``[2**(bits-1), min(order, 2**bits))``, and since
    ``2**bits`` is always above ``2**(bits-1)`` that interval is
    non-empty for exactly one condition: the order lies above
    ``2**(bits-1)``.  So this is not an approximation of the draw's
    behaviour, it is the draw's own emptiness test with the draw taken
    out.

    Deriving it from the interval rather than from ``bit_length(order)``
    matters for one shape of order.  A width ABOVE the order's bit length
    is unsupplyable, which a bit-length comparison does catch -- but a
    width EQUAL to it can be unsupplyable too, and that comparison does
    not: an order of exactly ``2**255`` has a bit length of 256 while the
    largest nonce below it, ``2**255 - 1``, is 255 bits wide.  Every one
    of the 26 registered curve orders is odd and so none of them is that
    shape, which is precisely why the fault could sit in the classifier
    unnoticed: it was reachable only through a synthetic order, and the
    self check used one.

    A *bits* below one is refused rather than computed, which also keeps
    it out of `nonce_of_bit_length()`: ``1 << (bits - 1)`` raises for a
    non-positive width, and a classifier that filters through this
    predicate never reaches that shift with one.
    """
    if bits < 1:
        return False
    return (1 << (bits - 1)) < order


# How one attempted signature came out.  The three cases have to stay
# distinguishable all the way up to the exit status, and a single
# ``except`` clause cannot do it: ``RSZeroError`` SUBCLASSES
# ``RuntimeError``, so catching the pair together silently equates "draw
# again" with "the entropy source is gone".
SIGN_OK = "ok"
SIGN_RETRY = "retry"
SIGN_FATAL = "fatal"


def sign_once(sk, digest, nonce, entropy):
    """One timed ``sign_digest()`` call, with the outcome categorised.

    Returns ``(SIGN_OK, (r, s, seconds))`` when a signature was
    produced, ``(SIGN_RETRY, reason)`` for a refusal that fresh inputs
    cure, and ``(SIGN_FATAL, reason)`` for one that they do not.

    The distinction is the whole point of the three-way return.  An ``r``
    or an ``s`` of exactly zero (``RSZeroError``) is this nonce and this
    digest being unlucky, and another draw signs perfectly well, so the
    caller retries and counts the drop.  Any other ``RuntimeError`` out
    of this path is ``Private_key.sign`` reporting that the entropy
    source it blinds its modular inversion with has failed, which its
    docstring states is NOT fixed by retrying.  Collapsing the two spends
    ``MAX_SIGN_RETRIES`` attempts per signature on a broken entropy
    source and then reports the run as though the machine had merely been
    unlucky, which is the one outcome a measurement instrument must never
    produce.

    The same entropy failure can also arrive as the source's own
    exception rather than as a ``RuntimeError``.  ``Private_key.sign``
    translates a refusal of the blinding draw it makes itself, but the
    nonce draw in ``keys.SigningKey.sign_number`` hands the entropy
    callable straight to ``util.randrange``, so a refusal there surfaces
    as the ``EnvironmentError`` or ``NotImplementedError`` that
    ``os.urandom`` raises -- one condition, two exception types, both
    fatal to a measurement.  Both are caught here so that the run ends in
    a status a caller can read rather than in a traceback.

    A clock that did not return a finite number of seconds is retryable
    rather than fatal: it is a fault of the machine and not of the
    signature, but letting one through would put a value into a sample
    that every statistic downstream would turn into something reading
    like a result.

    Nothing else is caught.  An exception this path does not document is
    a defect in the probe or in the library, and hiding it behind a drop
    count would be the same mistake in a quieter place.
    """
    try:
        started = CLOCK()
        signature = sk.sign_digest(
            digest, entropy=entropy, sigencode=raw_signature, k=nonce
        )
        elapsed = CLOCK() - started
    except RSZeroError:
        return (SIGN_RETRY, "r or s came out zero")
    except (EnvironmentError, NotImplementedError, RuntimeError) as error:
        return (SIGN_FATAL, "%s: %s" % (error.__class__.__name__, error))
    if not is_finite(elapsed):
        return (SIGN_RETRY, "the clock did not return a finite duration")
    return (SIGN_OK, (signature[0], signature[1], elapsed))


def minimum_of_signatures(sk, digest, nonce, repetitions, entropy):
    """Fastest of *repetitions* signatures over one fixed nonce.

    The minimum is the usual estimator here: scheduler interference and
    garbage collection can only ever make a sample slower, so the
    smallest of a handful of repetitions is the closest a script in this
    position gets to the cost of the arithmetic alone.

    Returns ``(SIGN_OK, seconds)`` once every repetition was timed, and
    otherwise the first refusal exactly as ``sign_once`` categorised it,
    so a fatal one reaches the caller as itself rather than as one more
    thing to retry.
    """
    best = None
    for _ in range(repetitions):
        status, payload = sign_once(sk, digest, nonce, entropy)
        if status != SIGN_OK:
            return (status, payload)
        if best is None or payload[2] < best:
            best = payload[2]
    if best is None:
        return (SIGN_RETRY, "no repetition was timed")
    return (SIGN_OK, best)


def warm_up(sk, digest, rounds):
    """Sign *rounds* times and discard everything, before any timing.

    The generator's precompute table is built lazily on its first
    multiplication, and that first call pays for the whole table.
    Without this the first recorded sample of a run is an outlier large
    enough to move a bucket median on its own.

    Returns the reason of a fatal refusal, or ``None`` when the warm-up
    finished.  A retryable refusal needs no attention here: the round is
    discarded either way, and the table was already built by the
    multiplication that ran before the signature was refused.
    """
    for _ in range(rounds):
        status, payload = sign_once(sk, digest, None, None)
        if status == SIGN_FATAL:
            return payload
    return None


WARM_UP_ROUNDS = 3


# --------------------------------------------------------------------
# Mode 1: controlled nonce bit widths.
# --------------------------------------------------------------------


# A repeated request for the same bucket width, which collapses into the
# first one.  Distinguished from the two substantive refusals below
# because there is nothing for a reader to act on: the width IS measured,
# once.
WIDTH_DUPLICATE = "duplicate"


def classified_widths(order, drops=CONTROLLED_BIT_DROPS, floor=MIN_NONCE_BITS):
    """Every requested bucket width, with the reason it cannot be timed.

    ``(bits, reason)`` in the order *drops* asks for them, *reason* being
    ``None`` for a width this curve can supply.  Two refusals are
    substantive and one is not:

    * a width below *floor* is narrower than this probe will time at all;
    * a width above the order's own bit length has NO valid nonce, and is
      named as that because it is the case a reader meets: a drop of
      ``-1`` against any curve;
    * a width the order cannot supply for any other reason is named
      through `width_is_supplyable()`, which decides it from the interval
      `nonce_of_bit_length()` would draw from rather than from a bit
      length.  The two are not the same test, and the difference is a
      whole width: an order of exactly ``2**255`` has a bit length of 256
      and no 256-bit nonce below it at all.  Classifying by bit length
      alone marked that width supplyable, handed it to the collection,
      and the collection then dropped the bucket on the ``None`` the draw
      returned -- the silence this function exists to prevent, arrived at
      through this function;
    * a repeat of a width already asked for is ``WIDTH_DUPLICATE``, which
      costs nothing and is not reported.

    Classifying instead of filtering is the whole point: a width the
    configuration asked for and this curve cannot supply used to vanish
    between `controlled_widths()` and the collection, so the report
    listed CONTROLLED_BIT_DROPS in its parameters and then quietly
    measured fewer buckets than it named, with nothing saying which one
    went missing or why.

    *drops* and *floor* are parameters so the classification can be
    exercised against fixed inputs without retuning the module.
    """
    top = bit_length(order)
    classified = []
    seen = []
    for drop in drops:
        bits = top - drop
        if bits in seen:
            classified.append((bits, WIDTH_DUPLICATE))
            continue
        seen.append(bits)
        if bits < floor:
            classified.append(
                (
                    bits,
                    "below the %d bit floor this probe will time" % (floor,),
                )
            )
        elif bits > top:
            classified.append(
                (
                    bits,
                    "wider than the %d bit order, so no nonce of that "
                    "width exists" % (top,),
                )
            )
        elif not width_is_supplyable(bits, order):
            classified.append(
                (
                    bits,
                    "no nonce below this %d bit order is %d bits wide, "
                    "so there is none to time" % (top, bits),
                )
            )
        else:
            classified.append((bits, None))
    return classified


def controlled_widths(order, drops=CONTROLLED_BIT_DROPS, floor=MIN_NONCE_BITS):
    """Descending bucket bit widths for a generator of this order.

    Only the widths the curve can actually supply, each once, widest
    first.  *drops* and *floor* carry through to `classified_widths()`.
    """
    widths = []
    for bits, reason in classified_widths(order, drops, floor):
        if reason is None:
            widths.append(bits)
    widths.sort(reverse=True)
    return widths


def refused_widths(order, drops=CONTROLLED_BIT_DROPS, floor=MIN_NONCE_BITS):
    """The requested widths this curve cannot supply, and why.

    Duplicates are left out: they are measured, once, so there is
    nothing to report about them.  *drops* and *floor* carry through to
    `classified_widths()`.
    """
    refused = []
    for bits, reason in classified_widths(order, drops, floor):
        if reason is None or reason == WIDTH_DUPLICATE:
            continue
        refused.append((bits, reason))
    return refused


def collect_controlled(sk, curve, rnd):
    """Time ``CONTROLLED_PER_BUCKET`` nonces at each bucket width.

    One observation per nonce, each the minimum of ``MIN_OF``
    repetitions.  Returns ``(buckets, rounds, drops)``, where *buckets*
    maps a bit width to its list of seconds and *rounds* maps the same
    width to the round each of those observations came from, aligned
    element for element.

    The buckets are interleaved rather than measured one after another,
    and this matters more than it looks.  A machine that speeds up over
    the course of a run -- caches filling, a frequency governor waking
    up -- would hand a block-ordered collection a clean monotone trend
    that has nothing to do with the nonce at all.  Taking one
    observation from every bucket per round spreads any such drift
    evenly across the buckets, and it is what makes a pair of
    observations comparable at all: the two came from the same round.
    The order within a round rotates so that no bucket is permanently
    first or last.

    The round each observation came from is returned rather than left
    implicit in its position, because a bucket that dropped an
    observation is one short of every other bucket from that point on.
    Reading position *i* of two buckets as "the same round" would then
    silently compare a round against its neighbour for the whole rest of
    the run, and a machine drifting over that run is exactly the
    confound the interleaving was there to remove.  Pairing is done on
    these round numbers instead -- see `round_matched_differences()`.

    Every nonce is drawn before any timing starts, so no randomness is
    consumed between the two clock readings.
    """
    order = curve.order
    digest = random_bytes(rnd, curve.baselen)
    fatal = warm_up(sk, digest, WARM_UP_ROUNDS)
    if fatal is not None:
        return ({}, {}, 0, fatal)
    plan = {}
    usable = []
    for bits in controlled_widths(order):
        nonces = []
        for _ in range(CONTROLLED_PER_BUCKET):
            nonces.append(nonce_of_bit_length(rnd, bits, order))
        plan[bits] = nonces
        if nonces and nonces[0] is not None:
            usable.append(bits)
    buckets = {}
    rounds = {}
    for bits in usable:
        buckets[bits] = []
        rounds[bits] = []
    drops = 0
    for round_index in range(CONTROLLED_PER_BUCKET):
        if not usable:
            break
        rotation = round_index % len(usable)
        for bits in usable[rotation:] + usable[:rotation]:
            status, payload = minimum_of_signatures(
                sk, digest, plan[bits][round_index], MIN_OF, None
            )
            attempts = 1
            while status == SIGN_RETRY and attempts < MAX_SIGN_RETRIES:
                attempts += 1
                retry = nonce_of_bit_length(rnd, bits, order)
                if retry is None:
                    break
                status, payload = minimum_of_signatures(
                    sk, digest, retry, MIN_OF, None
                )
            if status == SIGN_FATAL:
                # not a drop: a refusal a fresh nonce cannot cure makes
                # every remaining observation of this collection just as
                # unobtainable, so the collection ends here and says why
                return (buckets, rounds, drops, payload)
            if status != SIGN_OK:
                drops += 1
            else:
                buckets[bits].append(payload)
                rounds[bits].append(round_index)
    for bits in list(buckets.keys()):
        if not buckets[bits]:
            del buckets[bits]
            del rounds[bits]
    return (buckets, rounds, drops, None)


# --------------------------------------------------------------------
# Mode 2: the library draws the nonce, the probe recovers it afterwards.
# --------------------------------------------------------------------


def recover_nonce(order, secret, number, r, s):
    """The nonce behind one signature, from the private scalar.

    ``s == k**-1 * (h + d*r) mod n`` rearranges to
    ``k == s**-1 * (h + d*r) mod n``.  This is the same computation the
    external harness performs, and the same one an attacker performs
    after a successful lattice attack -- here it is legitimate, because
    the private scalar is the probe's own.

    Returns the recovered value without judging it; ``nonce_matches``
    below decides whether it is right.
    """
    return inverse_mod(s, order) * (number + secret * r) % order


def nonce_matches(curve, nonce, number, secret, r, s):
    """Whether *nonce* really is the nonce that produced ``(r, s)``.

    A probe that silently mis-recovered nonces would bucket its
    observations at random and then report reassuring noise, which is a
    worse outcome than not measuring at all, so this check is not
    optional -- and it takes two independent forms, because neither one
    alone is a check on the value.

    The first is the signing relation itself, ``s * k == h + d * r
    (mod n)``.  It pins the residue exactly, which the second form
    cannot: ``(-k) * G`` and ``k * G`` are reflections of each other and
    share an x coordinate, so an x comparison accepts ``n - k`` as
    readily as ``k``.  A value and its complement to the order need not
    have the same bit length, and the bit length is the whole quantity
    this script buckets by, so a sign error anywhere in the recovery
    would have reported a trend built from the wrong widths.  Under the
    relation above, ``n - k`` requires ``2 * (h + d * r) == 0 (mod n)``,
    which for a prime order and a non-zero right-hand side does not
    happen.

    The second is that ``r`` is the x coordinate of ``nonce * G``.  It is
    not implied by the first: the relation is what the recovery solved,
    so it holds for whatever ``(r, s)`` was fed in, correct or not, while
    re-deriving ``r`` goes back to the curve and checks the pair against
    it.  Together they catch both a wrong residue and a corrupted
    signature.

    A nonce outside ``[1, order)`` is rejected before either.
    """
    order = curve.order
    if nonce < 1 or nonce >= order:
        return False
    if s * nonce % order != (number + secret * r) % order:
        return False
    point = nonce * curve.generator
    # x() raises on the point at infinity, which the range check above
    # already excludes for every curve of prime order
    return point.x() % order == r


def collect_recovered(sk, curve, rnd, count):
    """Time *count* signatures, then recover and bucket every nonce.

    The nonce comes out of the signature by the standard relation
    ``k == s**-1 * (h + d*r) mod n`` and is then checked two ways by
    `nonce_matches()` -- against the signing relation, which pins the
    residue, and against the curve, which re-derives ``r`` from ``k*G``.
    A probe that silently mis-recovered nonces would bucket observations
    at random and report reassuring noise, so neither check is optional.

    Recovery runs after the timing loop, never inside it.  Returns a
    dict with the observations in collection order as ``(bits, seconds,
    attempt)`` triples, plus the drop and recovery-failure counts and the
    reason of a refusal that ended the collection early, if there was
    one.

    *attempt* is which signing attempt of the loop below produced the
    observation, and it is carried rather than reconstructed from the
    position in the returned list.  A refused signature, or a nonce that
    failed to confirm, leaves a hole: from that point on the list
    position of every later observation is smaller than the attempt it
    came from.  `matched_differences()` bounds a pair by how far apart
    the two were taken, and reading that bound off list positions would
    quietly let the gap grow past ``MAX_PAIR_GAP`` -- which is the whole
    protection against pairing two readings with a machine drift between
    them.
    """
    order = curve.order
    secret = sk.privkey.secret_multiplier
    entropy = seeded_entropy(rnd)
    length = curve.baselen
    fatal = warm_up(sk, random_bytes(rnd, length), WARM_UP_ROUNDS)
    collected = []
    drops = 0
    for attempt in range(count):
        if fatal is not None:
            break
        digest = random_bytes(rnd, length)
        payload = None
        status = SIGN_RETRY
        for _ in range(MAX_SIGN_RETRIES):
            status, payload = sign_once(sk, digest, None, entropy)
            if status != SIGN_RETRY:
                break
        if status == SIGN_FATAL:
            # the same reasoning as in `collect_controlled()`: a refusal a
            # fresh draw cannot cure ends the collection rather than
            # costing it one more observation
            fatal = payload
            break
        if status != SIGN_OK:
            drops += 1
            continue
        collected.append(
            (
                attempt,
                string_to_number(digest),
                payload[0],
                payload[1],
                payload[2],
            )
        )
    observations = []
    failures = 0
    for attempt, number, r, s, seconds in collected:
        nonce = recover_nonce(order, secret, number, r, s)
        if not nonce_matches(curve, nonce, number, secret, r, s):
            failures += 1
            continue
        observations.append((bit_length(nonce), seconds, attempt))
    return {
        "observations": observations,
        "drops": drops,
        "recovery_failures": failures,
        "attempted": count,
        "fatal": fatal,
    }


def bucket_prefix(observations, size):
    """Buckets built from the first *size* usable observations.

    *size* counts observations that were kept, not signing attempts, so
    a prefix is what an observer would have had once this many
    signatures had been timed and their nonces confirmed.
    """
    buckets = {}
    for entry in observations[:size]:
        bits = entry[0]
        if bits not in buckets:
            buckets[bits] = []
        buckets[bits].append(entry[1])
    return buckets


def reference_bit_length(buckets):
    """The largest POPULATED bit width, which is the reference bucket.

    The external harness pairs the maximum nonce bit size against each
    smaller one; this is that maximum.  Buckets that exist but hold no
    observation are skipped: an empty reference would leave every
    comparison with nothing to pair against and quietly produce an empty
    report rather than an answer.  Returns ``None`` when no bucket holds
    anything.
    """
    best = None
    for bits in buckets:
        if not buckets[bits]:
            continue
        if best is None or bits > best:
            best = bits
    return best


def testable_bit_lengths(buckets, reference_bits, minimum, limits=LIMITS):
    """Bucket widths eligible for a comparison, largest first.

    A bucket needs *minimum* observations to be tested, and at most
    ``limits["most"]`` are taken, so that the Bonferroni divisor
    reflects the comparisons that carry information rather than a tail of
    buckets holding a handful of samples each.

    *minimum* is a parameter rather than ``MIN_BUCKET_SAMPLES`` outright
    because the two modes populate their buckets differently.  Mode 2's
    bucket sizes are dictated by chance, so it needs the floor to stop a
    bucket of three observations from setting the trend.  Mode 1 chooses
    its bucket size, so its floor is ``CONTROLLED_MIN_SAMPLES``: lowering
    ``CONTROLLED_PER_BUCKET`` for a quick run must shrink the samples,
    not silently switch the whole battery off.
    """
    eligible = []
    for bits in buckets:
        if bits == reference_bits:
            continue
        if len(buckets[bits]) < minimum:
            continue
        eligible.append(bits)
    eligible.sort(reverse=True)
    return eligible[: limits["most"]]


def skip_reason(held, minimum, most):
    """Why `testable_bit_lengths()` passed a bucket over.

    It turns a bucket down for either of two reasons -- the bucket holds
    fewer than *minimum* observations, or it is eligible but falls
    outside the *most* widest that are compared -- and the report gave
    only the first of them, so a bucket dropped by the cap was named as
    holding too few observations when it held plenty.  A reader raising
    ``CONTROLLED_PER_BUCKET`` to answer that would have found the bucket
    still missing and no reason given anywhere.

    A bucket reaches the second case only by surviving the first, so the
    order of the two tests here is the order in `testable_bit_lengths()`
    and the two cannot both apply.
    """
    if held < minimum:
        return "holds fewer than %d observations" % (minimum,)
    return "outside the %d widest eligible buckets compared" % (most,)


def round_matched_differences(reference, reference_rounds, test, test_rounds):
    """Differences between observations taken in the SAME round.

    Mode 1 interleaves its buckets so that a pair of observations can be
    compared at all, and this is where that arrangement is cashed in.
    Position in the list is not enough on its own: `collect_controlled()`
    drops an observation whose signature was refused for every retry, so
    a bucket that lost one is one element short of the others from that
    point on and its position *i* holds a later round than theirs.
    Pairing on position would then compare round *i* against round
    *i + 1* for the whole rest of the run, and the difference between
    two rounds is however much the machine drifted in between -- the
    exact confound the interleaving exists to remove.

    Each bucket holds at most one observation per round, so matching on
    the round number is one to one without any further bookkeeping, and
    an unmatched round simply yields no pair.

    Reference minus test is the sign convention of the per-bucket table
    as well, so a positive difference always means "the narrower nonce
    was the faster one".
    """
    positions = {}
    for index in range(len(reference_rounds)):
        positions[reference_rounds[index]] = index
    differences = []
    for index in range(len(test_rounds)):
        other = positions.get(test_rounds[index])
        if other is None:
            continue
        differences.append(reference[other] - test[index])
    return differences


def matched_differences(
    observations, reference_bits, test_bits, limits=LIMITS
):
    """Proximity-matched differences, in microseconds, reference minus
    test.

    Mode 2 cannot pair by index: the reference bucket holds roughly half
    of all observations while a narrow bucket holds a few hundred, so
    observation *i* of the two was taken at quite different points in
    the run and their difference carries however much the machine
    drifted in between.  That is a confound big enough to manufacture a
    significant result out of nothing.

    Each test observation is therefore paired with a reference-bucket
    observation taken within ``limits["gap"]`` positions of it, and the
    pair is dropped when there is none.

    The position that bound is measured in is the signing attempt each
    observation came from, carried on the observation itself by
    `collect_recovered()`, and NOT the position in this list.  The two
    part company as soon as anything is dropped: a refused signature or
    an unconfirmed nonce leaves a hole, after which every later
    observation sits at a list position below the attempt it came from,
    and two observations a hundred attempts apart can end up sixteen
    list positions apart.  Reading the bound off list positions would
    therefore have let exactly the drift-carrying pairs through that the
    bound exists to refuse.

    The matching is ONE TO ONE: a reference observation serves exactly
    one test observation and is then spent.  That restriction is what
    makes the paired tests mean anything.  Letting a reference
    observation serve several neighbours is pseudoreplication: it reports
    more pairs than there were independent reference measurements, and
    the paired tests divide by the square root of that inflated count, so
    one slow reading reused by a dozen neighbours contributes the same
    large positive difference a dozen times over.  The median does not
    move, so nothing looks wrong in the table, while the t statistic
    grows on replicated rather than on independent evidence.

    The two devices answer two different confounds and both are needed.
    Proximity matching keeps a pair's two readings close together in the
    run, so their difference is not mostly machine drift; the one-to-one
    restriction keeps the pair count equal to the number of independent
    readings, so the divisor the paired tests use is the real one.
    Either device on its own leaves a route to a p-value the data does
    not support.

    The restriction costs sensitivity: fewer pairs survive, so a real
    dependence needs more observations before it is caught.  That is the
    trade this instrument makes deliberately, because a probe that can
    manufacture a detection cannot be trusted to report the absence of
    one.

    Pairs are taken greedily, earliest available reference first, which
    is the choice that maximises how many pairs survive -- so the
    restriction costs power only where the data genuinely cannot supply
    independent pairs.
    """
    references = []
    tests = []
    for index in range(len(observations)):
        entry = observations[index]
        if entry[0] == reference_bits:
            references.append(entry)
        elif entry[0] == test_bits:
            tests.append(entry)
    if not references or not tests:
        return []
    differences = []
    available = 0
    total = len(references)
    for entry in tests:
        attempt = entry[2]
        # skip references that are already spent, and those left so far
        # behind that neither this test observation nor any later one
        # could pair with them
        while (
            available < total
            and references[available][2] < attempt - limits["gap"]
        ):
            available += 1
        if available >= total:
            break
        candidate = references[available]
        if candidate[2] > attempt + limits["gap"]:
            # the earliest unspent reference is still in the future by
            # more than the bound; later test observations may reach it
            continue
        differences.append((candidate[1] - entry[1]) * 1e6)
        available += 1
    return differences


NO_BOOTSTRAP_NOTE = "not resampled: the decision does not read an interval"


def run_p_value_battery(differences):
    """The three p-value tests for one already paired set of differences.

    This is the whole of what a detection decision reads: the bootstrap
    interval is reported at a fixed 95 %, which no corrected alpha can be
    expressed in, so `battery_minimum_p()` never looks at it.  Anywhere
    the intervals are not going to be printed -- the prefix scan, which
    re-tests the same buckets at every sample count -- resampling them a
    thousand times per bucket per prefix is work whose result is thrown
    away, so that path calls this and `run_battery()` is reserved for the
    one place the intervals are shown.

    A set holding anything that is not a finite number is refused here as
    well as inside each test, and refused as *invalid* rather than merely
    untested: a bucket that held too few observations is an ordinary
    result to report, while one whose numbers are not numbers withdraws
    the verdict of the whole comparison it belongs to.
    """
    if not all_finite(differences):
        return declined_battery(len(differences), NON_FINITE_NOTE, valid=False)
    return {
        "tested": True,
        "valid": True,
        "reason": "",
        "pairs": len(differences),
        "sign": sign_test(differences),
        "t": paired_t_test(differences),
        "wilcoxon": wilcoxon_test(differences),
        "bootstrap": {
            "intervals": [],
            "used": 0,
            "note": NO_BOOTSTRAP_NOTE,
        },
    }


def run_battery(differences, seed):
    """All four tests, for the one report that prints the intervals.

    *seed* fixes the bootstrap resampling for this pair alone, so an
    interval is reproducible without depending on how many other pairs
    were evaluated first.
    """
    result = run_p_value_battery(differences)
    if result["tested"]:
        result["bootstrap"] = bootstrap_test(differences, random.Random(seed))
    return result


def declined_battery(pairs, reason, valid=True):
    """A battery result for a bucket that was not tested.

    *valid* is false only when the reason is that the numbers themselves
    could not be used; a bucket declined for holding too few
    observations is perfectly valid, it is simply empty of evidence.
    """
    return {
        "tested": False,
        "valid": valid,
        "reason": reason,
        "pairs": pairs,
        "sign": {
            "p": None,
            "method": "none",
            "pairs": 0,
            "positive": 0,
            "note": reason,
        },
        "t": {"p": None, "note": reason},
        "wilcoxon": {"p": None, "note": reason},
        "bootstrap": {"intervals": [], "used": 0, "note": reason},
    }


P_VALUE_TESTS = ["sign", "t", "wilcoxon"]

# The same three, paired with how the report speaks of them, for the
# lines that name a test that declined.  One list rather than two so a
# test cannot be added to the battery and left out of the diagnostics.
DECLINABLE_TESTS = [
    ("sign", "the sign test"),
    ("t", "the paired t test"),
    ("wilcoxon", "the Wilcoxon test"),
]


def battery_minimum_p(result):
    """Smallest p-value in *result*, with the test that produced it.

    Only the three p-value tests take part.  The bootstrap interval is
    reported at a fixed 95 %, which no corrected alpha can be read into,
    so it stays out of the decision.

    A p-value that is not a finite number takes no part either.  It is
    not a small p-value, and comparing one against a threshold answers
    false, so leaving it in would quietly turn an unusable number into a
    "not detected".  ``battery_is_valid()`` is what reports that such a
    number was there.
    """
    best = None
    which = "-"
    for name in P_VALUE_TESTS:
        probability = result[name]["p"]
        if not is_finite(probability):
            continue
        if best is None or probability < best:
            best = probability
            which = name
    return (best, which)


def battery_finite_p_count(result):
    """How many of *result*'s three p-value tests produced a number.

    The evidence one comparison contributed, counted rather than
    inferred.  Zero means no test in this battery produced a p-value
    that may be read: either the bucket was never tested, or every test
    that ran declined, or what it produced was not a finite number.  In
    all three cases the comparison says nothing, and a report that
    cannot tell those apart from "tested and did not reject" would turn
    the absence of evidence into a reassuring result.

    The same three tests as `battery_minimum_p()`, for the same reason:
    the bootstrap interval is fixed at 95 %, no corrected alpha can be
    read into it, and it therefore takes no part in any decision.
    """
    total = 0
    for name in P_VALUE_TESTS:
        if is_finite(result[name]["p"]):
            total += 1
    return total


def battery_is_valid(result):
    """Whether every number *result* carries may be read as one.

    False when the paired differences were not all finite, and false when
    a test that did run produced a p-value that is not a finite number.
    A battery that merely declined for want of data is valid: there is
    nothing wrong with its numbers, there are just not enough of them.
    """
    if not result.get("valid", True):
        return False
    for name in P_VALUE_TESTS:
        probability = result[name]["p"]
        if probability is not None and not is_finite(probability):
            return False
    return True


def batteries_are_valid(entries):
    """Whether every battery in *entries* may be read."""
    for _, result in entries:
        if not battery_is_valid(result):
            return False
    return True


def entries_minimum_p(entries):
    """Smallest p-value across *entries*, with its test and its bucket.

    Returns ``(p, test_name, bits)``, all three ``None``/``"-"`` when no
    entry produced a p-value that may be read.  Both the mode verdict and
    the last row of the prefix scan are this same number, which is why it
    is computed in one place: the scan's final prefix IS the full sample,
    so recomputing its tests would be running the identical three tests
    over the identical differences a second time.
    """
    best = None
    which = "-"
    where = None
    for bits, result in entries:
        probability, name = battery_minimum_p(result)
        if probability is None:
            continue
        if best is None or probability < best:
            best = probability
            which = name
            where = bits
    return (best, which, where)


def entries_finite_p_count(entries):
    """How many readable p-values *entries* produced altogether.

    The evidence behind a mode verdict or a prefix row.  Zero means not
    one comparison in the mode produced a number a threshold could be
    applied to, which is the state that must never be reported as a
    nondetection: `entries_minimum_p()` returns ``None`` for it, and
    ``None`` compares false against any threshold, so an unguarded
    ``best < threshold`` would quietly answer "not detected" to a
    question nothing was asked about.
    """
    total = 0
    for _, result in entries:
        total += battery_finite_p_count(result)
    return total


# --------------------------------------------------------------------
# Reporting.
#
# Everything goes to stdout.  No file is written and no directory is
# needed, so the script is safe to run from anywhere.  The machine
# readable block at the end carries the same numbers as the tables, for
# diffing one run against another.
# --------------------------------------------------------------------

RULE_WIDTH = 70

# how many skipped bucket widths to name per output line, chosen to keep
# the wrapped list inside RULE_WIDTH at its six-space indent -- the
# widest curve here needs 49 columns for twelve of them
DECLINED_PER_LINE = 12

CSV_ROWS = []

TREND_FORM = (
    "  {bits:>5} {n:>7} {median:>10} {mean:>10} {diff:>10} "
    "{se:>8} {zed:>7} {ref:>9}"
)

BATTERY_FORM = (
    "  {bits:>5} {pairs:>7} {sign:>11} {tvalue:>11} {wilcox:>11} " "{how:>6}"
)

BOOT_FORM = "  {bits:>5} {trim:>5} {low:>11} {high:>11} {excl:>6} {rows:>6}"

SCAN_FORM = (
    "  {size:>9} {ref:>5} {tested:>8} {alpha:>10} {minp:>11} {by:>10}"
    " {verdict:>9}"
)


def show(value, spec="%.2f"):
    """Render one numeric table cell; anything missing becomes ``-``."""
    if value is None:
        return "-"
    if value != value:
        return "-"
    return spec % (value,)


def show_p(value):
    """Render a p-value, or ``-`` when the test declined to run."""
    if value is None:
        return "-"
    return "%.2e" % (value,)


def to_micros(values):
    """Convert a list of seconds to a list of microseconds."""
    return [value * 1e6 for value in values]


def with_commas(number):
    """Group an integer's digits in threes.

    Hand-rolled because the ``,`` presentation type of ``str.format``
    only arrived in Python 2.7 and this package still supports 2.6.
    """
    digits = str(abs(int(number)))
    groups = []
    while len(digits) > 3:
        groups.insert(0, digits[-3:])
        digits = digits[:-3]
    groups.insert(0, digits)
    grouped = ",".join(groups)
    if number < 0:
        return "-" + grouped
    return grouped


def wrapped_lines(text, width, indent):
    """*text* greedily wrapped to *width*, each line prefixed *indent*.

    Hand-rolled for the same reason the declined-bucket list is: the
    report's column budget has to hold on every interpreter this package
    supports, and a wrapper whose defaults have moved between versions
    would not guarantee that.  Needed by the lines whose text is
    assembled at runtime -- the validity paragraph, and every line that
    quotes back a reason a measurement was not made -- since those are
    the only ones that cannot be wrapped where they are written.
    """
    lines = []
    current = ""
    for word in text.split():
        if not current:
            current = word
        elif len(current) + 1 + len(word) <= width:
            current += " " + word
        else:
            lines.append(indent + current)
            current = word
    if current:
        lines.append(indent + current)
    return lines


def print_rule(character):
    """A full-width horizontal rule."""
    print(character * RULE_WIDTH)


def print_section(title):
    """A section heading with an underline the width of the title."""
    print("")
    print(title)
    print("-" * len(title))


def print_banner():
    """The title block, including what the report does not assert."""
    print_rule("=")
    print(" minerva_probe.py")
    print(" nonce-bit-length timing probe for the ECDSA signing path")
    print(" CVE-2024-23342 / GHSA-wj6h-64fc-37mp / PYSEC-2026-1325")
    print(" CWE-203, CWE-208, CWE-385")
    print_rule("=")
    print("")
    print(
        "This report measures how strongly the duration of a signature\n"
        "tracks the bit length of the per-signature nonce, and how many\n"
        "timed signatures it takes before that dependence becomes\n"
        "statistically visible.  It is a measurement, not a"
        " certification:\n"
        "nothing here is a claim of constant-time execution, and a\n"
        "residual per-operation signal survives in pure Python whatever\n"
        "is done at the ladder level.  Read a smaller signal as a"
        " smaller\n"
        "signal and nothing more."
    )


def clock_granularity(resolution, reads, measured=True):
    """How the timer's granularity reads, including when it was not found.

    `measure_clock_resolution()` answers ``nan`` when it saw no non-zero
    gap at all, which a coarse timer can do however many readings it is
    given.  Formatting that with ``%.2e`` printed ``nan s``, which reads
    as a measured granularity of an unrepresentable size rather than as
    the absence of a measurement.  Said in words instead, with the read
    count that produced it.

    *measured* false is a third state, not a second: the run refused its
    settings and never read the clock at all.  That is not a granularity,
    and it is not a granularity that was looked for and not found either,
    so it says which of the two it is.

    The read count is rendered rather than formatted as a number.  This
    block is printed BEFORE a settings refusal -- deliberately, since a
    refusal is easier to act on beside the interpreter it was raised on
    -- so the line has to survive a ``CLOCK_READS`` that is not a number,
    which is one of the very edits that refusal exists to name.
    """
    if not measured:
        return "not measured (the settings below were refused first)"
    if not is_finite(resolution):
        return "not measured (no non-zero gap in %s reads)" % (reads,)
    return "%.2e s (smallest non-zero gap in %s reads)" % (resolution, reads)


def print_environment(resolution, measured=True):
    """The fingerprint without which a timing number means nothing."""
    print_section("environment")
    version = " ".join(sys.version.split())
    if ellipticcurve.GMPY:
        backend = "gmpy/gmpy2 mpz (ecdsa.ellipticcurve.GMPY = True)"
    else:
        backend = "pure-Python int (ecdsa.ellipticcurve.GMPY = False)"
    timer_name = getattr(CLOCK, "__name__", "unknown")
    rows = [
        ("python", version),
        ("implementation", platform.python_implementation()),
        ("platform", platform.platform()),
        ("ecdsa version", ecdsa.__version__),
        ("ecdsa module", ecdsa.__file__),
        ("integer backend", backend),
        ("timer", "timeit.default_timer -> %s" % (timer_name,)),
        (
            "timer granularity",
            clock_granularity(resolution, CLOCK_READS, measured),
        ),
    ]
    for label, value in rows:
        print("  {0:<18}: {1}".format(label, value))


def shown_alpha(alpha):
    """``ALPHA`` as the parameter block prints it.

    Rendered as text when it is not a number, for the reason
    `clock_granularity()` renders its read count as text: this block is
    printed BEFORE a settings refusal, so it has to survive every value
    that refusal exists to name -- and ``"%.1e" % "1e-6"`` raises.
    """
    if not is_real(alpha):
        return "%r" % (alpha,)
    return "%.1e" % (alpha,)


def shown_curves(names):
    """``CURVE_NAMES`` as the parameter block prints it.

    Joined when every entry could name a curve and rendered whole when
    they cannot, for the same reason `shown_alpha()` exists: a list
    holding anything but strings makes ``", ".join()`` raise, and this
    block is printed before the refusal that names the list.
    """
    if not is_sequence(names) or not every_curve_name(names):
        return "%r" % (names,)
    return ", ".join(names)


def print_parameters(threshold_note):
    """Every tunable, so the run can be reproduced from its output."""
    print_section("parameters")
    rows = [
        ("CURVE_NAMES", shown_curves(CURVE_NAMES)),
        ("REPEAT", REPEAT),
        ("CONTROLLED_PER_BUCKET", CONTROLLED_PER_BUCKET),
        ("MIN_OF", MIN_OF),
        ("CONTROLLED_BIT_DROPS", CONTROLLED_BIT_DROPS),
        ("MIN_NONCE_BITS", MIN_NONCE_BITS),
        ("MIN_BUCKET_SAMPLES", MIN_BUCKET_SAMPLES),
        ("CONTROLLED_MIN_SAMPLES", CONTROLLED_MIN_SAMPLES),
        ("MAX_TESTED_BUCKETS", MAX_TESTED_BUCKETS),
        ("MAX_PAIR_GAP", MAX_PAIR_GAP),
        ("SIGN_TEST_MIN_PAIRS", SIGN_TEST_MIN_PAIRS),
        ("EXACT_BINOM_MAX_N", EXACT_BINOM_MAX_N),
        ("BOOTSTRAP_RESAMPLES", BOOTSTRAP_RESAMPLES),
        ("BOOTSTRAP_MAX_PAIRS", BOOTSTRAP_MAX_PAIRS),
        ("BOOTSTRAP_MIN_SAMPLES", BOOTSTRAP_MIN_SAMPLES),
        ("TRIM_PROPORTIONS", TRIM_PROPORTIONS),
        ("PREFIX_SIZES", PREFIX_SIZES),
        ("MAX_SIGN_RETRIES", MAX_SIGN_RETRIES),
        ("WARM_UP_ROUNDS", WARM_UP_ROUNDS),
        ("ALPHA", shown_alpha(ALPHA)),
        ("SEED", SEED),
    ]
    for label, value in rows:
        print("  {0:<22}: {1}".format(label, value))
    print("")
    print("  " + threshold_note)
    print(
        "  the seed fixes nonce selection, digest selection and every\n"
        "  bootstrap resampling; the timings themselves are not\n"
        "  reproducible and are not expected to be"
    )


def print_anchors():
    """Observation counts published elsewhere, for scale."""
    print_section("calibration anchors (observations needed to detect)")
    for count, description in CALIBRATION_ANCHORS:
        print("  {0:>12}  {1}".format(with_commas(count), description))
    print("")
    print(
        "  the last anchor is the honest one: hardened compiled C still\n"
        "  leaked, it just took three orders of magnitude more samples\n"
        "  to see it"
    )


def print_trend(rows, reference_medians):
    """The per-bucket table: the primary visual evidence."""
    print(
        TREND_FORM.format(
            bits="bits",
            n="n",
            median="med(us)",
            mean="mean(us)",
            diff="d(r-t)",
            se="se",
            zed="|z|",
            ref="was(us)",
        )
    )
    for row in rows:
        if reference_medians is None:
            previous = "-"
        else:
            previous = show(reference_medians.get(row["bits"]), "%.1f")
        print(
            TREND_FORM.format(
                bits=row["bits"],
                n=row["n"],
                median=show(row["median_us"]),
                mean=show(row["mean_us"]),
                diff=show(row["diff_us"]),
                se=show(row["se_us"]),
                zed=show(row["abs_z"]),
                ref=previous,
            )
        )


def print_reason(text):
    """One line of assembled diagnostic prose, wrapped to the report.

    The reasons quoted back here are written by whichever test or bucket
    refused, so their length is not known where they are printed and they
    have to be wrapped at run time to stay inside the report's column
    budget.  Continuation lines are indented further than the first, so a
    wrapped reason cannot be misread as a second reason.
    """
    lines = wrapped_lines(text, RULE_WIDTH - 4, "")
    for index in range(len(lines)):
        if index:
            print("    " + lines[index])
        else:
            print("  " + lines[index])


def print_widths(widths):
    """The bucket widths of one decline, wrapped to the column budget.

    Wrapped by hand rather than with textwrap so the line stays inside
    the report's budget on every interpreter, and shared by every place
    that names a set of buckets.

    Indented one step deeper than a wrapped reason, so that three levels
    read as three things: the reason at two spaces, its continuation at
    four, and the buckets it applies to at six.  Without that, the tail
    of a long reason and the list of widths sat at the same depth and a
    reader had to parse the prose to tell which was which.
    """
    for start in range(0, len(widths), DECLINED_PER_LINE):
        print(
            "      %s bits"
            % (
                ", ".join(
                    [
                        str(value)
                        for value in widths[start : start + DECLINED_PER_LINE]
                    ]
                ),
            )
        )


def declined_tests(entries):
    """Which individual tests declined for which buckets, and what each said.

    ``(label, note, widths)`` for every distinct (test, reason) pair over
    the buckets whose battery actually RAN, in test order and then by
    reason.  A bucket that was never tested at all is left to
    `print_declined()`; this is the finer case, where a battery ran and
    one of its three tests refused the sample -- a sign test below its
    pair floor, a t test with no variance to divide by, a Wilcoxon test
    whose differences are all ties.

    Those refusals printed as a bare ``-`` in the table with the reason
    computed and then thrown away, so a reader could not tell a test that
    refused from one that answered with a large p-value.  Only one of the
    two says anything about a dependence.
    """
    grouped = {}
    for bits, result in entries:
        if not result["tested"]:
            continue
        for label, _ in DECLINABLE_TESTS:
            test = result[label]
            if test["p"] is not None:
                continue
            grouped.setdefault((label, test["note"]), []).append(bits)
    rows = []
    for label, spoken in DECLINABLE_TESTS:
        notes = []
        for key in grouped:
            if key[0] == label and key[1] not in notes:
                notes.append(key[1])
        notes.sort()
        for note in notes:
            rows.append((spoken, note, grouped[(label, note)]))
    return rows


def declined_intervals(entries):
    """Which buckets got no bootstrap interval, and what the resampler said.

    ``(note, widths)`` per distinct reason, over the buckets whose
    battery ran.  The bootstrap declines for reasons of its own -- too
    few rows to resample, or a ``TRIM_PROPORTIONS`` entry outside the
    domain `is_trim_proportion()` allows -- and those reasons were
    computed and never printed, so an empty interval column looked like
    an interval that happened to contain zero.
    """
    grouped = {}
    for bits, result in entries:
        if not result["tested"]:
            continue
        bootstrap = result.get("bootstrap")
        if bootstrap is None or bootstrap["intervals"]:
            continue
        grouped.setdefault(bootstrap["note"], []).append(bits)
    rows = []
    for note in sorted(grouped.keys()):
        rows.append((note, grouped[note]))
    return rows


def print_declined(entries):
    """One line naming the buckets that were not tested, and why.

    They are kept out of the tables because a row of dashes carries no
    information, but they are named rather than dropped silently: a
    reader has to be able to see that a bucket existed and was passed
    over, and on what grounds.
    """
    reasons = {}
    for bits, result in entries:
        if result["tested"]:
            continue
        reasons.setdefault(result["reason"], []).append(bits)
    for reason in sorted(reasons.keys()):
        widths = reasons[reason]
        print_reason("not tested, %s: %d bucket(s)" % (reason, len(widths)))
        print_widths(widths)


def print_test_declines(entries):
    """Name every individual test that refused a sample, and why.

    A dash in the table above is neither a large p-value nor a small
    one: it is a test that declined, and nothing follows from it in
    either direction.  Printed only when there is something to print, so
    a run where all three tests answered everywhere says nothing extra.
    """
    rows = declined_tests(entries)
    if not rows:
        return
    print(
        "  a - above is a test that DECLINED, not a p-value: nothing was\n"
        "  established by it either way"
    )
    for spoken, note, widths in rows:
        print_reason(
            "%s declined for %d bucket(s): %s" % (spoken, len(widths), note)
        )
        print_widths(widths)


def print_interval_declines(entries):
    """Name the buckets that got no interval, and what the resampler said."""
    rows = declined_intervals(entries)
    if not rows:
        return
    print(
        "  a - in the interval columns is a resampling that was not\n"
        "  carried out, not an interval that happens to contain zero"
    )
    for note, widths in rows:
        print_reason("no interval for %d bucket(s): %s" % (len(widths), note))
        print_widths(widths)


def print_battery(entries):
    """p-values for every bucket compared against the reference."""
    print(
        BATTERY_FORM.format(
            bits="bits",
            pairs="pairs",
            sign="sign_p",
            tvalue="t_p",
            wilcox="wilcox_p",
            how="binom",
        )
    )
    for bits, result in entries:
        if not result["tested"]:
            continue
        print(
            BATTERY_FORM.format(
                bits=bits,
                pairs=result["pairs"],
                sign=show_p(result["sign"]["p"]),
                tvalue=show_p(result["t"]["p"]),
                wilcox=show_p(result["wilcoxon"]["p"]),
                how=result["sign"]["method"],
            )
        )
    print(
        "  t_p is exact Student's t; wilcox_p is a tie-corrected normal\n"
        "  approximation; binom says whether sign_p came from the exact\n"
        "  integer binomial tail or from the incomplete beta form of it"
    )
    print_test_declines(entries)
    print_declined(entries)


def print_bootstrap(entries):
    """95 % percentile intervals on the two trimmed-mean estimators."""
    print(
        BOOT_FORM.format(
            bits="bits",
            trim="trim",
            low="lo(us)",
            high="hi(us)",
            excl="excl0",
            rows="rows",
        )
    )
    for bits, result in entries:
        if not result["tested"]:
            continue
        bootstrap = result["bootstrap"]
        if not bootstrap["intervals"]:
            # tested for the three p-value tests, but short of
            # BOOTSTRAP_MIN_SAMPLES, so the interval was refused
            print(
                BOOT_FORM.format(
                    bits=bits,
                    trim="-",
                    low="-",
                    high="-",
                    excl="-",
                    rows=bootstrap["used"],
                )
            )
            continue
        for interval in bootstrap["intervals"]:
            # the battery is handed microseconds, so the interval is
            # already in microseconds and needs no scaling here
            print(
                BOOT_FORM.format(
                    bits=bits,
                    trim="%.2f" % (interval["trim"],),
                    low=show(interval["low"], "%.3f"),
                    high=show(interval["high"], "%.3f"),
                    excl="yes" if interval["excludes_zero"] else "no",
                    rows=bootstrap["used"],
                )
            )
    print(
        "  intervals are at a fixed 95 %, as in the external harness, so\n"
        "  they are descriptive only and take no part in the corrected\n"
        "  alpha decision below"
    )
    print_interval_declines(entries)


def print_scan(detected_at, rows, total):
    """The headline: the earliest prefix at which anything still rejects.

    The rows are the prefixes of ``PREFIX_SIZES`` the battery was re-run
    over, so the resolution of the answer is the spacing of that list:
    it brackets the true threshold from above rather than pinning it,
    the threshold lying between the rejecting prefix and the one before.

    ``ref`` is the reference bucket that prefix chose and ``alpha`` the
    corrected significance level that prefix was judged at.  Both are
    per row rather than per run because both are properties of the data
    an observer would have had at that sample count -- see
    `scan_prefixes()`.

    Which of the four headline states is printed is decided by
    `scan_headline()`, which is also the cell recorded in the machine
    readable block, so the prose and the CSV can never say different
    things about the same run.
    """
    print(
        SCAN_FORM.format(
            size="N",
            ref="ref",
            tested="buckets",
            alpha="alpha",
            minp="min_p",
            by="test",
            verdict="verdict",
        )
    )
    for row in rows:
        print(
            SCAN_FORM.format(
                size=row["size"],
                ref=show(row["reference"], "%d"),
                tested=row["tested"],
                alpha="%.2e" % (row["threshold"],),
                minp=show_p(row["min_p"]),
                by=row["by"],
                verdict=scan_verdict(row),
            )
        )
    print("")
    print(
        "  alpha is Bonferroni corrected per row: ALPHA %.1e divided by\n"
        "  the buckets that prefix could test, never by a count taken\n"
        "  from the finished run" % (ALPHA,)
    )
    print(
        "  a verdict of no data is a prefix that produced no p-value at\n"
        "  all -- no reference bucket, no bucket big enough to compare\n"
        "  against it, no pair inside the proximity bound, or no test\n"
        "  willing to run.  It is not a - : nothing was tested there, so\n"
        "  nothing about that sample count was established either way"
    )
    headline = scan_headline(detected_at, rows)
    if headline == "invalid":
        print(
            "  smallest detectable N : unavailable -- a prefix carried a\n"
            "  value that is not a finite number"
        )
        print(
            "  no bound can be read from this run: an unusable number is\n"
            "  neither a detection nor the absence of one"
        )
        return
    if headline == "insufficient":
        print(
            "  smallest detectable N : insufficient evidence -- no prefix\n"
            "  produced a p-value that could be read"
        )
        print(
            "  no bound can be read from this run: not one statistical\n"
            "  comparison was carried out, so this is the absence of\n"
            "  evidence and NOT evidence of absence.  Collect more\n"
            "  observations, or lower MIN_BUCKET_SAMPLES, so that at\n"
            "  least one bucket can be compared against the reference"
        )
        return
    if headline == "none":
        tested = scan_tested_sizes(rows)
        bound = tested[-1]
        print(
            "  smallest detectable N : not detected at N <= %s"
            % (with_commas(bound),)
        )
        print(
            "  the dependence is not resolved by this instrument at this\n"
            "  sample count, which is not the same as its absence; raise\n"
            "  REPEAT to push the bound further out"
        )
        if len(tested) < len(rows):
            print(
                "  %d of the %d prefixes above produced a p-value and the\n"
                "  bound is read from those alone; the remaining %d tested\n"
                "  nothing, so no sample count of theirs is bounded by it"
                % (len(tested), len(rows), len(rows) - len(tested))
            )
        if bound != total:
            print(
                "  %s observations were collected in all: the bound stops\n"
                "  at the largest prefix a test actually ran over"
                % (with_commas(total),)
            )
        return
    print("  smallest detectable N : %s" % (with_commas(headline),))
    print(
        "  a dependence on nonce bit length is already visible at\n"
        "  that sample count"
    )


# --------------------------------------------------------------------
# Analysis assembly.
# --------------------------------------------------------------------


def trend_rows(buckets, reference_bits):
    """One row per bucket, ordered from the widest nonce downwards.

    ``d(r-t)`` is the reference median minus this bucket's median, so it
    is positive whenever the narrower nonces signed faster.  ``se`` is
    the standard error of that difference of medians and ``|z|`` their
    ratio -- a scale for the gap, deliberately separate from the tests.
    """
    reference = buckets.get(reference_bits, [])
    reference_us = to_micros(reference)
    reference_median = median(reference_us)
    rows = []
    for bits in sorted(buckets.keys(), reverse=True):
        sample_us = to_micros(buckets[bits])
        row_median = median(sample_us)
        difference = reference_median - row_median
        standard_error = float("nan")
        absolute_z = float("nan")
        if bits != reference_bits and reference:
            standard_error = pooled_median_se(reference_us, sample_us)
            if standard_error == standard_error and standard_error > 0.0:
                absolute_z = abs(difference) / standard_error
        rows.append(
            {
                "bits": bits,
                "n": len(sample_us),
                "median_us": row_median,
                "mean_us": mean(sample_us),
                "diff_us": difference,
                "se_us": standard_error,
                "abs_z": absolute_z,
            }
        )
    return rows


def monotone_summary(rows, minimum):
    """How strongly the medians follow the nonce bit width.

    Returns a dict with ``rho``, ``span_us``, ``span_in_se``, ``falling``
    and ``steps``.  ``rho`` is the Spearman correlation between bit width
    and median, and ``span_us`` the spread of those medians.  Neither
    means anything alone: ``rho`` near +1 says only that the ordering is
    there, and a perfect ordering over a span at the noise floor is what
    pure chance produces across a handful of buckets.  The leak looks
    like both at once -- an ordering and a span far above the noise.

    ``span_in_se`` is the honest version of that second half: the span
    divided by the typical standard error of a bucket's difference of
    medians, so it says how many noise widths the spread covers rather
    than how many microseconds.  Microseconds are not comparable between
    machines; noise widths are.  ``falling`` counts the adjacent bucket
    pairs, widest first, whose median dropped, out of ``steps``.

    Only buckets holding at least *minimum* observations take part: a
    bucket with three samples has a median that moves by tens of
    microseconds on its own and would otherwise set the span
    single-handedly.
    """
    nan = float("nan")
    widths = []
    medians = []
    errors = []
    for row in rows:
        if row["n"] < minimum:
            continue
        widths.append(row["bits"])
        medians.append(row["median_us"])
        if row["se_us"] == row["se_us"] and row["se_us"] > 0.0:
            errors.append(row["se_us"])
    if len(medians) < 2:
        return {
            "rho": nan,
            "span_us": nan,
            "span_in_se": nan,
            "falling": 0,
            "steps": 0,
        }
    falling = 0
    for index in range(len(medians) - 1):
        if medians[index + 1] < medians[index]:
            falling += 1
    span = max(medians) - min(medians)
    span_in_se = nan
    if errors:
        typical = median(errors)
        if typical > 0.0:
            span_in_se = span / typical
    return {
        "rho": spearman_rho(widths, medians),
        "span_us": span,
        "span_in_se": span_in_se,
        "falling": falling,
        "steps": len(medians) - 1,
    }


def print_monotone(summary, minimum):
    """Say whether an ordering is present, how big it is, and on what
    scale.

    A summary computed from fewer than two eligible buckets says so
    outright.  Its cells render as ``-`` and its step count as ``0 of
    0``, and neither of those is a flat trend: no trend was computed at
    all, and the difference matters for the same reason it does in the
    detection verdict below.
    """
    print(
        "  monotone trend: rho = %s over %d buckets, span = %s us"
        % (
            show(summary["rho"], "%+.3f"),
            summary["steps"] + 1,
            show(summary["span_us"]),
        )
    )
    print(
        "  that span is %s times the typical bucket standard error, and\n"
        "  %d of %d adjacent steps fall as the nonce narrows, counting\n"
        "  only buckets holding at least %d observations"
        % (
            show(summary["span_in_se"], "%.1f"),
            summary["falling"],
            summary["steps"],
            minimum,
        )
    )
    if summary["steps"] < 1:
        print(
            "  fewer than two buckets cleared that floor, so no trend was\n"
            "  computed: the dashes are absent numbers and the zero steps\n"
            "  are none counted, neither of them a flat trend"
        )


def bucket_differences(
    buckets, rounds, reference_bits, bits, observations, limits=LIMITS
):
    """Paired differences for one bucket, in microseconds.

    Proximity-matched on the signing attempt when *observations* is
    supplied -- the Mode 2 case, where the buckets have wildly different
    sizes -- and matched on the round otherwise, which is what Mode 1's
    interleaved collection makes possible.
    """
    if observations is not None:
        return matched_differences(observations, reference_bits, bits, limits)
    return round_matched_differences(
        to_micros(buckets[reference_bits]),
        rounds[reference_bits],
        to_micros(buckets[bits]),
        rounds[bits],
    )


def battery_entries(
    buckets,
    reference_bits,
    minimum,
    base_seed,
    observations=None,
    rounds=None,
    limits=LIMITS,
):
    """Run the battery for every testable bucket against the reference.

    Buckets that were passed over are still listed, carrying a declined
    result and the reason `skip_reason()` gives for it, so the report can
    name what was skipped and on what grounds rather than leaving a
    reader to guess at a bucket that simply is not there.
    """
    entries = []
    if not buckets.get(reference_bits):
        return entries
    testable = testable_bit_lengths(buckets, reference_bits, minimum, limits)
    for bits in sorted(buckets.keys(), reverse=True):
        if bits == reference_bits:
            continue
        if bits not in testable:
            entries.append(
                (
                    bits,
                    declined_battery(
                        0,
                        skip_reason(
                            len(buckets[bits]), minimum, limits["most"]
                        ),
                    ),
                )
            )
            continue
        differences = bucket_differences(
            buckets, rounds, reference_bits, bits, observations, limits
        )
        if not differences:
            # the two modes match pairs differently, so they run out of
            # pairs for different reasons and each says its own
            if observations is not None:
                reason = "no pair within %d signing attempts" % (
                    limits["gap"],
                )
            else:
                reason = "no round in common with the reference bucket"
            entries.append((bits, declined_battery(0, reason)))
            continue
        entries.append(
            (bits, run_battery(differences, base_seed + 10007 * bits))
        )
    return entries


def scan_prefixes(observations, minimum, full_entries=None, limits=LIMITS):
    """Re-run the p-value tests over growing prefixes of *observations*.

    Returns ``(detected_at, rows)``, where *detected_at* is the smallest
    prefix at which any p-value test rejected at that prefix's own
    corrected alpha, or ``None``.  Each prefix is a prefix of the
    collection order, so it is exactly what an observer would have had
    after that many signatures.

    EVERYTHING a prefix is judged by is derived from the prefix itself:
    which bucket is the reference, which buckets hold enough
    observations to be compared against it, and therefore how many
    comparisons the Bonferroni correction divides by.  Taking any of the
    three from the finished run would let an observation the observer
    had not yet made decide how the ones they had are read, and the
    number this function reports is a claim about what was knowable at
    that sample count -- so it would not be that number any more.  The
    reference bucket is the clearest case: the widest nonce seen in the
    first five hundred signatures is often narrower than the widest seen
    in twenty thousand, and comparing against a bucket that is empty
    until later gives that prefix no comparisons at all.

    *full_entries* is the battery already computed over the complete
    sample, if there is one.  The last prefix IS the complete sample --
    same reference, same buckets, same paired differences -- so its
    p-values are those entries' p-values, and recomputing them would run
    the identical three tests over the identical numbers a second time.

    Only the three p-value tests run here.  The bootstrap intervals are
    fixed at 95 %, take no part in a corrected-alpha decision, and are
    not printed for a prefix, so resampling them a thousand times per
    bucket per prefix would be work whose result is discarded.
    """
    total = len(observations)
    sizes = []
    for size in limits["sizes"]:
        # a rung of none or fewer is not a prefix of anything: zero
        # selects an empty sample and a negative one slices the TAIL off
        # instead, which then printed as a row of negative N.  The
        # settings refusal names such a ladder before a run reaches
        # here; this keeps the function itself total, since the ladder
        # is a parameter
        if size < 1:
            continue
        if size <= total and size not in sizes:
            sizes.append(size)
    if total > 0 and total not in sizes:
        sizes.append(total)
    sizes.sort()
    rows = []
    detected_at = None
    for size in sizes:
        prefix = observations[:size]
        buckets = bucket_prefix(prefix, size)
        reference_bits = reference_bit_length(buckets)
        best = None
        which = "-"
        testable = []
        valid = True
        # how many readable p-values this prefix produced.  Counted, not
        # inferred from *best*: a prefix that tested nothing and a prefix
        # that tested and did not reject both leave *best* unusable for
        # the purpose -- the first as None, the second as a number no
        # smaller than the threshold -- and only the second one is a
        # result.  See `scan_has_evidence()`.
        finite = 0
        if reference_bits is not None:
            testable = testable_bit_lengths(
                buckets, reference_bits, minimum, limits
            )
        if full_entries is not None and size == total:
            valid = batteries_are_valid(full_entries)
            best, which, _ = entries_minimum_p(full_entries)
            finite = entries_finite_p_count(full_entries)
        else:
            for bits in testable:
                differences = matched_differences(
                    prefix, reference_bits, bits, limits
                )
                if not differences:
                    continue
                result = run_p_value_battery(differences)
                finite += battery_finite_p_count(result)
                if not battery_is_valid(result):
                    valid = False
                    continue
                probability, name = battery_minimum_p(result)
                if probability is None:
                    continue
                if best is None or probability < best:
                    best = probability
                    which = name
        comparisons = max(1, len(testable))
        threshold = corrected_alpha(comparisons, limits)
        # an invalid prefix rejects nothing: a number that cannot be read
        # is not a small p-value, and letting one set the headline would
        # report a bound this instrument did not establish
        rejected = valid and best is not None and best < threshold
        if rejected and detected_at is None:
            detected_at = size
        rows.append(
            {
                "size": size,
                "reference": reference_bits,
                "tested": len(testable),
                "comparisons": comparisons,
                "threshold": threshold,
                "min_p": best,
                "by": which,
                "rejected": rejected,
                "valid": valid,
                "finite_p": finite,
                "evidence": finite > 0,
            }
        )
    return (detected_at, rows)


def scan_tested_sizes(rows):
    """Prefix sizes that actually produced a readable p-value.

    A bound of the form "not detected at N <= x" is a claim about
    prefixes a test was run over.  A prefix that produced no p-value at
    all was not tested at any threshold, so it carries no such claim and
    is left out of the set the bound is read from.
    """
    sizes = []
    for row in rows:
        if row["valid"] and row["evidence"]:
            sizes.append(row["size"])
    return sizes


def scan_has_evidence(rows):
    """Whether any prefix in *rows* produced a readable p-value.

    False for a scan whose every prefix found no reference bucket, no
    bucket large enough to compare against it, no pair inside the
    proximity bound, or no test willing to run.  Each of those leaves
    every ``min_p`` at ``None`` and every ``rejected`` at false, which
    reads exactly like a run that tested everything and found nothing --
    and is the opposite.  Nothing was measured, so there is no bound to
    report, and this predicate is what keeps the two apart.
    """
    return len(scan_tested_sizes(rows)) > 0


def scan_headline(detected_at, rows):
    """The smallest-N cell of the machine readable block, and the state
    `print_scan()` prints.

    One of four:

    * ``invalid`` -- a prefix carried a number that could not be read.
      Not a detection and not the absence of one.
    * ``insufficient`` -- no prefix produced a p-value at all, so
      nothing was measured.  Also not the absence of a detection: an
      untested prefix cannot bound anything, and reporting one as
      "not detected" would manufacture a reassuring headline out of
      zero evidence.
    * ``none`` -- a battery ran and its readable p-values did not reject
      at the corrected alpha.  This one IS a result: the bound belongs to
      the prefixes named by `scan_tested_sizes()`.
    * the prefix size itself -- the smallest sample count at which
      something rejected.

    The report and this cell are the same decision so that they cannot
    disagree: `print_scan()` prints what this function returns rather
    than deriving the state a second time from the same rows.
    """
    for row in rows:
        if not row["valid"]:
            return "invalid"
    if not scan_has_evidence(rows):
        return "insufficient"
    if detected_at is None:
        return "none"
    return detected_at


def scan_verdict(row):
    """The per-prefix cell of the printed scan table.

    ``no data`` is the state F-03 of the review found missing: it was
    printed as ``-``, which the column legend reads as "nothing rejected
    here", when in fact nothing was tested here.
    """
    if not row["valid"]:
        return "invalid"
    if not row["evidence"]:
        return "no data"
    if row["rejected"]:
        return "detected"
    return "-"


def scan_outcome(row):
    """The per-prefix cell of the machine readable scan record.

    The same four states as `scan_verdict()`, spelled for a column that
    is grepped rather than read.
    """
    verdict = scan_verdict(row)
    if verdict == "invalid":
        return "invalid"
    if verdict == "no data":
        return "insufficient"
    if verdict == "detected":
        return "yes"
    return "no"


# --------------------------------------------------------------------
# Machine readable mirror of every table above.
# --------------------------------------------------------------------


def record(*fields):
    """Append one comma separated record to the machine readable block."""
    CSV_ROWS.append(",".join([str(field) for field in fields]))


def csv_safe(text):
    """*text* with the separator taken out, for a free-text CSV field.

    Only the validity records carry prose, and a comma inside one would
    silently add a column to a block whose whole purpose is to be split
    on commas.  Semicolons read the same to a human and cost nothing.
    """
    return str(text).replace(",", ";")


def record_trend(mode, curve_name, rows):
    """Mirror a per-bucket table."""
    for row in rows:
        record(
            "bucket",
            mode,
            curve_name,
            row["bits"],
            row["n"],
            show(row["median_us"], "%.4f"),
            show(row["mean_us"], "%.4f"),
            show(row["diff_us"], "%.4f"),
            show(row["se_us"], "%.4f"),
            show(row["abs_z"], "%.4f"),
        )


def record_battery(mode, curve_name, entries):
    """Mirror a p-value table and its bootstrap intervals."""
    for bits, result in entries:
        record(
            "test",
            mode,
            curve_name,
            bits,
            result["pairs"],
            show_p(result["sign"]["p"]),
            result["sign"]["method"],
            show_p(result["t"]["p"]),
            show_p(result["wilcoxon"]["p"]),
        )
        for interval in result["bootstrap"]["intervals"]:
            record(
                "boot",
                mode,
                curve_name,
                bits,
                "%.2f" % (interval["trim"],),
                show(interval["low"], "%.4f"),
                show(interval["high"], "%.4f"),
                "yes" if interval["excludes_zero"] else "no",
            )


def record_monotone(mode, curve_name, summary):
    """Mirror a monotone-trend line."""
    record(
        "trend",
        mode,
        curve_name,
        show(summary["rho"], "%+.4f"),
        show(summary["span_us"], "%.4f"),
        show(summary["span_in_se"], "%.4f"),
        summary["falling"],
        summary["steps"],
    )


def print_csv_block():
    """Print the machine readable block, with a legend for each record."""
    print_section("machine readable summary")
    print(
        "  every line below starts with CSV so it can be extracted with\n"
        "  a single grep and diffed between two runs"
    )
    print("")
    print(
        "  CSV,bucket,mode,curve,bits,n,median_us,mean_us,diff_us,"
        "se_us,abs_z"
    )
    print("  CSV,test,mode,curve,bits,pairs,sign_p,binom,t_p,wilcoxon_p")
    print("  CSV,boot,mode,curve,bits,trim,ci_lo_us,ci_hi_us,excludes0")
    print("  CSV,trend,mode,curve,rho,span_us,span_in_se,falling,steps")
    print(
        "  CSV,scan,curve,n,reference_bits,buckets,alpha,min_p,test," "outcome"
    )
    print(
        "  a test record whose p-values are all - is a bucket that was\n"
        "  not tested; it is kept here so two runs stay diffable"
    )
    print(
        "  a trend record whose rho and span are - was not computed at\n"
        "  all: fewer than two buckets cleared the floor, so its 0 of 0\n"
        "  steps are none counted rather than a flat trend"
    )
    print(
        "  a scan record carries the reference bucket and the corrected\n"
        "  alpha that prefix was judged at, both derived from that prefix\n"
        "  alone; they change down the column as later buckets appear"
    )
    print(
        "  a scan record whose last field is invalid, and a detect record\n"
        "  whose smallest_n is invalid, are not a detection and not the\n"
        "  absence of one: either a value that is not a finite number\n"
        "  reached a comparison, or a recovered nonce failed to confirm\n"
        "  and the bucketing itself cannot be trusted"
    )
    print(
        "  insufficient is the other state that is not a result: a scan\n"
        "  record carries it when that prefix produced no p-value at all,\n"
        "  and a detect record carries it when no prefix of the whole run\n"
        "  did.  It is deliberately not no: nothing was compared, so\n"
        "  nothing was found absent.  none, in a detect record, is the\n"
        "  one that IS a result -- a battery ran and did not reject"
    )
    print("  CSV,detect,curve,smallest_n,threshold,comparisons,total")
    print("  CSV,collect,curve,attempted,dropped,recovery_failures")
    print("  CSV,status,scope,description")
    print("  CSV,verdict,state,exit_status,problems")
    print(
        "  there is exactly one verdict record and it is the run's own\n"
        "  conclusion: reported means every comparison the run was asked\n"
        "  for was carried out and nothing was recorded against it, so\n"
        "  the numbers are evidence whether or not they detected\n"
        "  anything; unavailable means they are not, and then one status\n"
        "  record names each reason.  A detection does NOT make a run\n"
        "  unavailable -- gate automation on this record, not on whether\n"
        "  a smallest_n was found"
    )
    print("")
    for row in CSV_ROWS:
        print("CSV," + row)


# --------------------------------------------------------------------
# Per-curve driver.
# --------------------------------------------------------------------


def find_named_curve(name):
    """The registered curve called *name*, or ``None``."""
    for candidate in curves:
        if candidate.name == name:
            return candidate
    return None


# What a requested curve turns out to be.  Three outcomes, because the
# two that cannot be measured cannot be measured for different reasons
# and a reader has to be told which one they are in.
CURVE_RUNNABLE = "runnable"
CURVE_UNKNOWN = "unknown"
CURVE_EDWARDS = "edwards"


def curve_dispatch(name):
    """``(state, curve)`` for a requested curve name.

    ``(CURVE_RUNNABLE, curve)`` when this probe can time it,
    ``(CURVE_UNKNOWN, None)`` when nothing is registered under the name,
    and ``(CURVE_EDWARDS, curve)`` when it is registered but has no
    ``sign_digest()`` path -- ``keys.SigningKey.sign_digest()`` rejects an
    Edwards curve outright, so there is nothing to time even though the
    curve exists.

    Separated from the loop that consumes it so the decision can be
    exercised against real registered names in the self check.  The loop
    itself then has one branch instead of two, and neither branch can
    forget to account for what it skipped.
    """
    candidate = find_named_curve(name)
    if candidate is None:
        return (CURVE_UNKNOWN, None)
    if isinstance(candidate.curve, ellipticcurve.CurveEdTw):
        return (CURVE_EDWARDS, candidate)
    return (CURVE_RUNNABLE, candidate)


def skipped_curve_line(state):
    """What the report prints for a curve it cannot measure."""
    if state == CURVE_UNKNOWN:
        return "skipped: no curve is registered under that name"
    if state == CURVE_EDWARDS:
        return (
            "skipped: sign_digest() rejects Edwards curves, so there is "
            "no ECDSA signing path to time here"
        )
    return "skipped: this curve was not measured"


def skipped_curve_note(state):
    """Why a skipped curve produced no evidence, for the validity list."""
    if state == CURVE_UNKNOWN:
        return (
            "no curve is registered under that name, so none of the "
            "evidence this run was asked for on it was produced"
        )
    if state == CURVE_EDWARDS:
        return (
            "an Edwards curve has no sign_digest() path to time, so "
            "asking for it produced no evidence"
        )
    return (
        "this curve was not measured, and the reason was not recorded, "
        "so nothing it was asked for can be read as evidence"
    )


def skipped_curve_problems(name, state):
    """``(scope, description)`` for each mode of a skipped curve.

    Recorded per MODE rather than per curve so that the scopes in the
    problem list are the same scopes as in the evidence registry.  When
    they differ, `note_missing_evidence()` finds no problem under the
    scope it is looking at and appends its own generic one, and the
    validity section then names the same skip twice in two different
    vocabularies.
    """
    problems = []
    for scope in curve_mode_scopes(name):
        problems.append((scope, skipped_curve_note(state)))
    return problems


def skipped_curve_evidence(name):
    """``(scope, False)`` for every mode of a skipped curve.

    Pure, so the self check can assemble a synthetic run out of real
    dispatch decisions and pin the tally that run would report.
    """
    evidence = []
    for scope in curve_mode_scopes(name):
        evidence.append((scope, False))
    return evidence


def skipped_curve_fields(name):
    """The machine readable ``detect`` record of a skipped curve.

    Written rather than left out for the reason the other two
    non-detections are written: a record that is simply absent from one
    of two reports being diffed reads as an oversight, while
    ``insufficient`` says that nothing was compared.
    """
    return ("detect", name, "insufficient", "-", "-", 0)


def note_skipped_curve(name, state):
    """Account for a curve the run was asked for and could not measure.

    One problem and one evidence record per mode, and one machine
    readable row, so the validity tally, the problem list, the CSV block
    and the exit status all see the same skip.  This is the whole of the
    accounting a skipped curve needs, in one call, because the two paths
    that reach it used to do only part of it.
    """
    for scope, description in skipped_curve_problems(name, state):
        note_problem(scope, description)
    note_unproduced(name)
    record(*skipped_curve_fields(name))


def corrected_alpha(comparisons, limits=LIMITS):
    """Bonferroni-corrected significance level.

    ``ALPHA / len(k_sizes)`` in the external harness, where the divisor
    is the number of nonce bit sizes compared against the reference.
    """
    if comparisons < 1:
        return limits["alpha"]
    return limits["alpha"] / comparisons


def detection_state(entries, threshold):
    """The verdict *entries* support at *threshold*, as one of four words.

    ``unavailable`` when a comparison carried a value that could not be
    read, ``insufficient`` when no comparison produced a p-value at all,
    and ``detected`` / ``not detected`` when one did.  The middle state
    is the one that must not collapse into the last: `entries_minimum_p()`
    answers ``None`` for a mode whose every bucket declined, ``None``
    compares false against any threshold, and an unguarded
    ``best < threshold`` would therefore print "not detected" for a mode
    that tested nothing whatsoever.
    """
    if not batteries_are_valid(entries):
        return "unavailable"
    if entries_finite_p_count(entries) < 1:
        return "insufficient"
    best, _, _ = entries_minimum_p(entries)
    if best < threshold:
        return "detected"
    return "not detected"


def print_detection(entries, threshold, comparisons):
    """Whether any bucket rejected at the corrected alpha, and which.

    An invalid battery anywhere in *entries* withdraws the verdict
    outright.  It is not turned into a "not detected": a comparison whose
    numbers could not be read says nothing either way, and saying nothing
    is what is printed.  A mode in which no comparison produced a
    p-value is reported the same way and for the same reason, under its
    own word -- see `detection_state()`.
    """
    best, which, where = entries_minimum_p(entries)
    print(
        "  corrected alpha = %.3e (ALPHA %.1e / %d comparisons)"
        % (threshold, ALPHA, comparisons)
    )
    state = detection_state(entries, threshold)
    if state == "unavailable":
        print(
            "  verdict: unavailable -- a comparison carried a value that\n"
            "  is not a finite number, so no verdict can be read from "
            "this\n  mode"
        )
        return
    if state == "insufficient":
        tested = 0
        for _, result in entries:
            if result["tested"]:
                tested += 1
        print(
            "  verdict: insufficient evidence -- %d of the %d bucket(s)\n"
            "  listed above were tested and none of them produced a\n"
            "  p-value that could be read, so this mode is neither a\n"
            "  detection nor the absence of one; the reason each bucket\n"
            "  was skipped is named in the table" % (tested, len(entries))
        )
        return
    if state == "detected":
        print(
            "  verdict: detected -- %s rejects at %d bits, p = %.3e"
            % (which, where, best)
        )
    else:
        print(
            "  verdict: not detected -- smallest p = %.3e (%s at %d "
            "bits)" % (best, which, where)
        )


def report_mode(
    mode,
    curve,
    buckets,
    minimum,
    base_seed,
    show_reference,
    observations=None,
    rounds=None,
):
    """Print every table for one mode, and mirror it into the CSV block.

    *observations* selects the pairing: supplied for Mode 2, where the
    pairs have to be matched by proximity in the signing order.  Mode 1
    passes *rounds* instead and its pairs are matched on the round each
    observation came from.

    Returns ``(reference_bits, entries)`` so the caller can reach the
    verdict from the battery that was just printed instead of running it
    a second time -- both would give the same answer, since the seeds are
    fixed, but only one of them is honest about the cost.  Either element
    is ``None`` when there was nothing to report.
    """
    reference_bits = reference_bit_length(buckets)
    if reference_bits is None:
        print("  no observations were collected for this mode")
        return (None, None)
    rows = trend_rows(buckets, reference_bits)
    reference_medians = None
    if show_reference and curve.name == "NIST256p":
        reference_medians = REFERENCE_MEDIANS_NIST256P
    print("")
    print(
        "  reference bucket: %d bits, n = %d"
        % (reference_bits, len(buckets[reference_bits]))
    )
    print_trend(rows, reference_medians)
    record_trend(mode, curve.name, rows)
    if reference_medians is not None:
        print(
            "  was(us) is the median this bucket showed on NIST256p "
            "before\n  any hardening, on another machine: compare the "
            "shape of the\n  column, never the absolute values"
        )
    summary = monotone_summary(rows, minimum)
    print_monotone(summary, minimum)
    record_monotone(mode, curve.name, summary)
    if len(rows) < 2:
        print("  only one bucket was populated, so there is nothing to")
        print("  compare it against")
        return (reference_bits, None)
    entries = battery_entries(
        buckets, reference_bits, minimum, base_seed, observations, rounds
    )
    if not entries:
        print("  no comparison bucket was available")
        return (reference_bits, None)
    if observations is None:
        print("  pairs are matched on the round each observation came")
        print("  from, not on its position: the buckets were interleaved,")
        print("  so two observations of the same round were taken next to")
        print("  each other, and a dropped observation costs its own pair")
        print("  rather than shifting every pair after it")
    else:
        print(
            "  pairs are proximity-matched one to one: each observation\n"
            "  is paired with a reference-bucket observation taken at\n"
            "  most %d signing attempts away, and each reference\n"
            "  observation is used by exactly one pair, so a single slow\n"
            "  reading cannot be counted many times over" % (MAX_PAIR_GAP,)
        )
    print("")
    print_battery(entries)
    record_battery(mode, curve.name, entries)
    print("")
    print_bootstrap(entries)
    return (reference_bits, entries)


def probe_curve(curve, index):
    """Run both modes against *curve* and print the whole report."""
    print_section(
        "%s -- order %d bits, digest %d bytes"
        % (curve.name, bit_length(curve.order), curve.baselen)
    )
    signing_key = SigningKey.generate(curve)
    base_seed = SEED + 1000003 * index

    print("")
    print(" mode 1: injected nonces of a known bit width")
    print(
        "  %d nonces per bucket, each the fastest of %d signatures, "
        "injected\n  through the documented k= parameter of "
        "sign_digest()" % (CONTROLLED_PER_BUCKET, MIN_OF)
    )
    # a width the configuration asked for and this curve cannot supply is
    # named here rather than left to disappear between the parameter list
    # and the table below
    refused = refused_widths(curve.order)
    if refused:
        print("  requested widths this curve cannot supply:")
        for refused_bits, refused_reason in refused:
            print_reason("%d bits: %s" % (refused_bits, refused_reason))
    (
        controlled,
        controlled_rounds,
        controlled_drops,
        controlled_fatal,
    ) = collect_controlled(signing_key, curve, random.Random(base_seed + 1))
    if controlled_fatal is not None:
        print("  the collection stopped early:")
        for line in wrapped_lines(
            str(controlled_fatal), RULE_WIDTH - 4, "    "
        ):
            print(line)
        print(
            "  A refusal of this kind is not cured by another draw, so\n"
            "  what was collected before it is reported and this mode is\n"
            "  not evidence."
        )
        note_problem(
            mode_scope(curve.name, 1),
            "signing stopped the controlled collection before it "
            "finished: %s" % (controlled_fatal,),
        )
    if controlled_drops:
        print(
            "  %d observations were dropped after %d refused attempts "
            "each;\n  each costs the pair of its own round and nothing "
            "else" % (controlled_drops, MAX_SIGN_RETRIES)
        )
    reference_bits, entries = report_mode(
        "mode1",
        curve,
        controlled,
        CONTROLLED_MIN_SAMPLES,
        base_seed + 11,
        True,
        None,
        controlled_rounds,
    )
    controlled_scope = mode_scope(curve.name, 1)
    if entries:
        comparisons = max(
            1,
            len(
                testable_bit_lengths(
                    controlled, reference_bits, CONTROLLED_MIN_SAMPLES
                )
            ),
        )
        threshold = corrected_alpha(comparisons)
        controlled_state = detection_state(entries, threshold)
        print("")
        print_detection(entries, threshold, comparisons)
    else:
        # said outright rather than left as silence: a mode that printed
        # no verdict at all is easy to read, in a report of this length,
        # as a mode that found nothing
        controlled_state = "insufficient"
        print("")
        print(
            "  verdict: insufficient evidence -- this mode produced no\n"
            "  comparison to run the tests over, so it is neither a\n"
            "  detection nor the absence of one"
        )
        note_problem(
            controlled_scope,
            "the controlled comparison this run was asked for produced no "
            "testable pair of buckets",
        )
    # a state of insufficient or unavailable is the verdict being
    # withheld, and the report says so in words -- but words are not what
    # a caller reading the exit status sees, so the same two states are
    # recorded here.  A battery that RAN over buckets and produced no
    # readable p-value from any of them reaches this line with entries in
    # hand, which is why the state rather than the emptiness of the
    # entry list is what decides it.
    if controlled_state == "insufficient" and entries:
        note_problem(
            controlled_scope,
            "every bucket of the controlled comparison declined, so this "
            "mode carried out no statistical comparison",
        )
    elif controlled_state == "unavailable":
        note_problem(
            controlled_scope,
            "a bucket of the controlled comparison carried a value that "
            "is not a finite number, so no verdict can be read from it",
        )
    note_evidence(controlled_scope, state_is_comparison(controlled_state))

    print("")
    print(" mode 2: the library draws the nonce, the probe recovers it")
    print(
        "  %s signatures, timed one shot each, then bucketed by the "
        "bit\n  length of the nonce recovered from the signature"
        % (with_commas(REPEAT),)
    )
    recovered_scope = mode_scope(curve.name, 2)
    collected = collect_recovered(
        signing_key, curve, random.Random(base_seed + 2), REPEAT
    )
    observations = collected["observations"]
    if collected["fatal"] is not None:
        print("  the collection stopped early:")
        for line in wrapped_lines(
            str(collected["fatal"]), RULE_WIDTH - 4, "    "
        ):
            print(line)
        print(
            "  A refusal of this kind is not cured by another draw, so\n"
            "  what was collected before it is reported and this mode is\n"
            "  not evidence."
        )
        note_problem(
            recovered_scope,
            "signing stopped the recovered collection before it "
            "finished: %s" % (collected["fatal"],),
        )
    print(
        "  attempted %s, dropped %d, recovery failures %d, usable %s"
        % (
            with_commas(collected["attempted"]),
            collected["drops"],
            collected["recovery_failures"],
            with_commas(len(observations)),
        )
    )
    record(
        "collect",
        curve.name,
        collected["attempted"],
        collected["drops"],
        collected["recovery_failures"],
    )
    if collected["recovery_failures"]:
        # every observation is bucketed by the bit length of a nonce this
        # probe believes it recovered; one that could not be confirmed
        # means that belief is wrong somewhere, and there is no way to
        # know where.  A trend, a p-value or a smallest-N read off
        # buckets that may hold observations at the wrong width is worse
        # than no number at all, because it looks exactly like one that
        # can be trusted.  So mode 2 stops here rather than continuing
        # past a warning.
        print(
            "  mode 2 stops here.  %d nonce(s) failed to confirm, so the\n"
            "  bit width every observation is bucketed by cannot be "
            "trusted;\n  no trend, no p-value, no verdict and no smallest "
            "N are\n  reported for this curve.  Investigate before reading "
            "any\n  number from this mode." % (collected["recovery_failures"],)
        )
        record("detect", curve.name, "invalid", "-", "-", len(observations))
        note_problem(
            recovered_scope,
            "%d recovered nonce(s) did not match their signature, which "
            "invalidates the bucketing this mode reports by"
            % (collected["recovery_failures"],),
        )
        note_evidence(recovered_scope, False)
        return
    if not observations:
        print("  no usable observations, mode 2 cannot be reported")
        note_problem(
            recovered_scope,
            "no signature of this curve produced a usable observation, so "
            "this mode measured nothing",
        )
        # recorded rather than left out: a detect record that is simply
        # absent from one of two reports being diffed is easy to read as
        # an oversight, while insufficient says what happened
        record("detect", curve.name, "insufficient", "-", "-", 0)
        note_evidence(recovered_scope, False)
        return
    full_buckets = bucket_prefix(observations, len(observations))
    reference_bits, entries = report_mode(
        "mode2",
        curve,
        full_buckets,
        MIN_BUCKET_SAMPLES,
        base_seed + 21,
        False,
        observations,
    )
    if reference_bits is None:
        record(
            "detect", curve.name, "insufficient", "-", "-", len(observations)
        )
        note_problem(
            recovered_scope,
            "no bucket of recovered nonces held enough observations to "
            "serve as a reference, so nothing could be compared",
        )
        note_evidence(recovered_scope, False)
        return
    # the scan derives its own reference bucket and its own correction at
    # every prefix; nothing about the finished run is handed to it, and
    # the entries already computed above are handed over only so the last
    # prefix -- which is the finished run -- is not tested twice
    detected_at, scan = scan_prefixes(
        observations, MIN_BUCKET_SAMPLES, entries
    )
    print("")
    print(" mode 2: smallest observation count that still detects")
    print_scan(detected_at, scan, len(observations))
    for row in scan:
        record(
            "scan",
            curve.name,
            row["size"],
            show(row["reference"], "%d"),
            row["tested"],
            "%.3e" % (row["threshold"],),
            show_p(row["min_p"]),
            row["by"],
            scan_outcome(row),
        )
    last = scan[-1]
    headline = scan_headline(detected_at, scan)
    record(
        "detect",
        curve.name,
        headline,
        "%.3e" % (last["threshold"],),
        last["comparisons"],
        len(observations),
    )
    # the same two states Mode 1 records, and for the same reason: this
    # mode can reach here having compared nothing -- every bucket of
    # every prefix below the testable floor, or no pair inside the
    # proximity bound -- and the reference bucket exists in that case, so
    # the guard above it cannot see the difference.  The headline is what
    # the report itself printed, so recording from it keeps the exit
    # status and the prose deciding from one place.
    if headline == "insufficient":
        note_problem(
            recovered_scope,
            "no prefix of the recovered observations produced a p-value, "
            "so this mode carried out no statistical comparison",
        )
    elif headline == "invalid":
        note_problem(
            recovered_scope,
            "a prefix of the recovered observations carried a value that "
            "is not a finite number, so no verdict can be read from it",
        )
    note_evidence(recovered_scope, state_is_comparison(headline))


def exit_status():
    """``EXIT_REPORTED`` when the report is evidence, else the other one.

    One recorded problem is enough to withhold ``EXIT_REPORTED``: the
    report was asked for a specific set of measurements, and a caller
    reading only the status has no way to tell which part of it went
    missing, so anything short of all of them has to read as unavailable.
    A measurement that produced no comparison withholds it too, whether
    or not anything was recorded against it -- see `report_status()`.
    """
    return report_status(PROBLEMS, EVIDENCE)


def note_missing_evidence():
    """Record a problem for any measurement that compared nothing.

    Every such measurement already records one where it happens, and
    this is the backstop that keeps the exit status and the validity
    section from ever disagreeing with each other: the status refuses
    ``EXIT_REPORTED`` for an incomplete registry regardless, so a scope
    that reached the end without a problem of its own would otherwise
    fail the run without appearing in the list of what failed it.

    A mode whose curve was already ruled out as a whole counts as
    recorded -- see `problem_covers()` -- because the reason is one fact
    about the curve and the reader needs it once, not once per mode.

    Which scopes those are is `unexplained_scopes()`, kept separate so
    the self check can pin the decision without writing to either
    registry.
    """
    for scope in unexplained_scopes(PROBLEMS, EVIDENCE):
        note_problem(
            scope,
            "this measurement carried out no statistical comparison, so "
            "it is neither a detection nor the absence of one",
        )


def print_settings_refusal(complaints):
    """Name the settings this run will not measure under, and record them.

    Printed instead of a measurement, not alongside one: every complaint
    `configuration_problems()` returns is a setting whose answer is
    already fixed before a signature is timed, so spending minutes
    producing that answer would only lend it an authority it does not
    have.

    Each constant is named on its own line and recorded through
    `note_problem()`, which is what carries it into the validity section,
    into the machine readable rows, and into the exit status -- so a
    caller reading only the CSV block sees which edit to undo.
    """
    print_section("settings refused")
    print(
        "  nothing was measured.  A setting below either decides the\n"
        "  verdict before any signature is timed, so this run would have\n"
        "  printed a conclusion that is a property of the setting rather\n"
        "  than of the signing path, or leaves a collection or an\n"
        "  estimator unable to produce a number at all -- a bucket\n"
        "  nothing is timed into, an interval resampled from fewer pairs\n"
        "  than the interval's own floor admits, a prefix that is really\n"
        "  the sample with its tail cut off.  The self check was not run\n"
        "  either, for the same reason: its synthetic datasets cannot be\n"
        "  read under these settings.  Restore the constant named below\n"
        "  and run it again."
    )
    print("")
    for name, complaint in complaints:
        print("  %s:" % (name,))
        for line in wrapped_lines(complaint, RULE_WIDTH - 4, "    "):
            print(line)
        note_problem(name, complaint)


def print_validity():
    """Say whether this report is evidence, and name what stopped it.

    Printed before the machine readable block so the same conclusion
    reaches a reader and a script, and so every problem lands in the CSV
    rows alongside the numbers it disqualifies.

    The favourable sentence is derived from what was recorded rather
    than asserted: it names how many comparisons the run was asked for
    and how many it carried out, so it cannot claim a comparison that
    never happened.  The count it is asked for includes the curves that
    never reached a measurement -- an unregistered name, an Edwards curve
    -- because `note_skipped_curve()` registers both of their modes; a
    denominator that counted only the curves which got as far as being
    measured would have understated what the run was asked for.
    """
    print_section("validity")
    note_missing_evidence()
    produced, asked = evidence_tally(EVIDENCE)
    if report_status(PROBLEMS, EVIDENCE) == EXIT_REPORTED:
        print(
            "  comparisons carried out: %d of the %d this run was asked\n"
            "  for, and no signature refusal stopped a collection.  The\n"
            "  numbers above are usable as evidence, whether or not they\n"
            "  detected a dependence.  exit status %d."
            % (produced, asked, EXIT_REPORTED)
        )
        record("verdict", "reported", EXIT_REPORTED, 0)
        return
    print(
        "  comparisons carried out: %d of the %d this run was asked for."
        % (produced, asked)
    )
    print(
        "  the numbers above are NOT usable as evidence.  What follows\n"
        "  is what this run was asked for and did not produce, or\n"
        "  produced from a collection that cannot be vouched for.  exit\n"
        "  status %d, which is this script's 'analysis unavailable'."
        % (EXIT_UNAVAILABLE,)
    )
    print("")
    for scope, description in PROBLEMS:
        print("  %s:" % (scope,))
        for line in wrapped_lines(description, RULE_WIDTH - 4, "    "):
            print(line)
        record("status", scope, csv_safe(description))
    print("")
    print(
        "  detecting a dependence, or failing to, is NOT what sets this\n"
        "  status: a complete report exits %d either way, because the\n"
        "  'before' half of a before/after comparison has to be\n"
        "  collectable too" % (EXIT_REPORTED,)
    )
    record("verdict", "unavailable", EXIT_UNAVAILABLE, len(PROBLEMS))


def print_closing(elapsed):
    """Total cost of the run, and what the numbers do and do not mean."""
    print_section("summary")
    print("  total elapsed: %.1f s" % (elapsed,))
    print("")
    print(
        "  What this report supports: a comparison.  Run it against two\n"
        "  revisions of the arithmetic layer and the difference between\n"
        "  the two reports -- the flattening of the per-bucket medians,\n"
        "  the collapse of rho and of the span, the growth of the\n"
        "  smallest detectable N -- is measured evidence about the\n"
        "  nonce bit-length dependence of the signing path."
    )
    print("")
    print(
        "  One trap when reading two reports side by side: removing a\n"
        "  dependence on the nonce also tightens the noise floor, because\n"
        "  the operation count stops varying between repetitions of the\n"
        "  same measurement.  The span in microseconds and the span in\n"
        "  standard errors therefore move by different factors, and the\n"
        "  ratio understates the change.  Compare the microsecond spans\n"
        "  for the size of the effect, read the span in standard errors\n"
        "  as whether the effect is resolvable on this machine, and let\n"
        "  the corrected-alpha verdict settle detectability."
    )
    print("")
    print(
        "  What it does not support: any claim that the dependence is\n"
        "  gone.  Absence of detection at some N is a bound set by this\n"
        "  instrument and this machine, not a property of the code, and\n"
        "  a residual per-operation signal remains in pure Python\n"
        "  regardless: CPython integers are variable width and the\n"
        "  field arithmetic defers some reductions on purpose.  Nothing\n"
        "  above is a claim of constant-time execution.  The reference\n"
        "  point worth remembering is the third calibration anchor --\n"
        "  hardened compiled C still leaked about 34 ns, and it took\n"
        "  43,190,069 observations to see."
    )


# --------------------------------------------------------------------
# Self check.  The decision paths of the report above, exercised
# against synthetic inputs that hold no timing at all, before a single
# signature is measured.
#
# What it covers is the one mistake this instrument can make that
# nothing else would catch: printing a reassuring verdict out of an
# empty comparison.  A prefix with no reference bucket, no bucket large
# enough to compare against it, no pair inside the proximity bound, or
# no test willing to run leaves every p-value at ``None`` and every
# rejection false -- which in the numbers alone is indistinguishable
# from a run that tested everything and found nothing.  Only one of the
# two is a result, and the states that keep them apart are what is
# checked here.
#
# It lives inside this script rather than in the unit suite next to the
# operation-count tests because that suite cannot reach it: this module
# runs its measurement on import, deliberately, in the straight-line
# shape of ``speed.py``, so importing it from a test would start a
# multi-minute timing run.  The checks are written as explicit
# comparisons feeding a failure list rather than as ``assert``
# statements because ``python -O`` removes assert statements outright,
# and a self check that disappears under an optimisation flag would
# leave these states unguarded exactly where someone had asked for less
# overhead.
# --------------------------------------------------------------------

# The two bit widths the synthetic datasets use.  The values are
# arbitrary; only their order matters, since `reference_bit_length()`
# takes the widest populated bucket as the reference.
CHECK_REFERENCE_BITS = 256
CHECK_TEST_BITS = 255

# A third width, narrower than both, and a fourth wider than both, for
# the datasets that need the reference bucket to change from one prefix
# to the next.
CHECK_OTHER_BITS = 250
CHECK_WIDER_BITS = 300

# Observations per bucket, and the testable floor the synthetic
# datasets are judged at -- the same number, so that a dataset is
# refused for the reason under test rather than for its size.
#
# Fixed here rather than read from MIN_BUCKET_SAMPLES so that retuning
# that constant for a run cannot make these checks fail for a reason
# that has nothing to do with the states they cover.  It has to be a
# multiple of the balanced pattern's length, so that exactly half of
# that dataset's differences come out positive, and that is checked.
CHECK_PAIRS = 32
CHECK_MINIMUM = CHECK_PAIRS

# How many p-values a dataset of this size can carry is not a constant:
# it follows the sign test's live floor, and `check_finite()` below
# derives it.

# A plausible signing duration in seconds.  Nothing reads it as one; it
# is only the base that the synthetic microsecond offsets are added to.
CHECK_BASE_SECONDS = 1e-3

# A synthetic generator order for the width classification, and the
# nonce-width floor that classification is exercised at.  The order is
# ODD, and the largest integer of its width, for the same reason every
# one of the 26 registered curve orders is odd: a nonce of the order's
# own bit width has to EXIST for the widest requested bucket to be a
# bucket.  The floor is fixed here rather than read from MIN_NONCE_BITS
# for the same reason every other bound is.
CHECK_ORDER_BITS = 256
CHECK_ORDER = (1 << CHECK_ORDER_BITS) - 1
CHECK_FLOOR = 8

# And the one shape of order for which the widest requested width cannot
# be supplied at all: an exact power of two.  Its bit length is
# CHECK_ORDER_BITS, so a classifier that reads supplyability off a bit
# length calls that width supplyable, while the largest nonce below the
# order -- ``2**255 - 1`` -- is a bit NARROWER than the order's width.
# No registered curve is this shape, which is exactly why it belongs in a
# fixture: it is the only way to exercise the refusal, and the self check
# used to state the wrong answer for it.
CHECK_POWER_ORDER = 1 << (CHECK_ORDER_BITS - 1)

# One curve name of each kind the driver can be given: one this probe can
# time, one that is registered and has no ``sign_digest()`` path, and one
# that is not registered at all.  The first two are REAL registered names
# rather than stand-ins, because the classification they exercise reads
# the registry and the curve's own type; the third is checked to be
# absent from the registry before it is relied on, so a name that became
# a curve upstream cannot quietly turn that case into a different one.
CHECK_RUNNABLE_CURVE = "NIST256p"
CHECK_EDWARDS_CURVE = "Ed25519"
CHECK_MISSING_CURVE = "NoSuchCurve256"

# Drops that ask for one width of each kind: the order's own width and
# two narrower ones the curve can supply, one wider than the order (no
# nonce has it), and one so far below the order that it falls under the
# floor.  Held in the order they are asked in, which is the order they
# are reported in.
CHECK_DROPS = [1, 0, 4, -1, CHECK_ORDER_BITS - CHECK_FLOOR + 2]

# A trim proportion that is not one, for the bootstrap's refusal.  Below
# zero is the fabricating case -- the cut goes negative and the "trimmed
# mean" becomes the sample's upper tail -- and at one half is the
# mislabelling one, where the cuts meet and the estimator answers with
# the median under a label that says otherwise.
CHECK_BAD_TRIM = -0.1
CHECK_MEETING_TRIM = 0.5

# The widest trim the bootstrap will still resample under, one step
# inside the bound, so that the accepting side of `every_trim()` is
# pinned at the boundary rather than only in its comfortable middle.
CHECK_WIDEST_TRIM = 0.49

# A complete set of measurement settings whose every value is usable, so
# that a check can name exactly ONE constant by breaking one entry of it.
#
# Fixed here rather than read from the live constants, for the reason
# CHECK_GAP is: a run that retunes a measurement constant is asking for a
# different MEASUREMENT, not for different DECISION PATHS, and fixtures
# that moved with the constants reported a retuned configuration as a
# broken report.  The values equal the shipped defaults where there is
# one, except that the two list settings are shortened -- their length
# is nothing these checks read.
CHECK_SETTINGS = {
    "REPEAT": 20000,
    "CONTROLLED_PER_BUCKET": 80,
    "MIN_OF": 5,
    "MIN_NONCE_BITS": 8,
    "MIN_BUCKET_SAMPLES": 32,
    "CONTROLLED_MIN_SAMPLES": 32,
    "BOOTSTRAP_RESAMPLES": 1000,
    "BOOTSTRAP_MAX_PAIRS": 2000,
    "BOOTSTRAP_MIN_SAMPLES": 50,
    "CLOCK_READS": 20000,
    "WARM_UP_ROUNDS": 3,
    "MAX_SIGN_RETRIES": 8,
    "EXACT_BINOM_MAX_N": 1000,
    "SEED": 12345,
    "MEDIAN_SE_FACTOR": 1.2533,
    "TRIM_PROPORTIONS": [0.05, 0.45],
    "PREFIX_SIZES": [500, 1000],
    "CONTROLLED_BIT_DROPS": [0, 1, 4],
    "CURVE_NAMES": ["NIST256p"],
}

# One broken value per execution-critical constant, as
# ``(name, value)`` in the order `measurement_problems()` reports them.
# Each breaks its own constant and nothing else, which is what lets the
# checks below assert that exactly one name comes back -- and, read
# together, that every constant in the mapping above is reachable by the
# table at all.
CHECK_BROKEN_SETTINGS = [
    ("REPEAT", 0),
    ("CONTROLLED_PER_BUCKET", 0),
    ("MIN_OF", 0),
    ("MIN_NONCE_BITS", 0),
    ("MIN_BUCKET_SAMPLES", 0),
    ("CONTROLLED_MIN_SAMPLES", 0),
    ("BOOTSTRAP_RESAMPLES", 0),
    ("BOOTSTRAP_MAX_PAIRS", 0),
    ("CLOCK_READS", 0),
    ("WARM_UP_ROUNDS", 0),
    ("MAX_SIGN_RETRIES", 0),
    ("BOOTSTRAP_MIN_SAMPLES", -1),
    ("EXACT_BINOM_MAX_N", -1),
    ("SEED", 1.5),
    ("MEDIAN_SE_FACTOR", 0.0),
    ("TRIM_PROPORTIONS", [CHECK_MEETING_TRIM]),
    ("PREFIX_SIZES", [-100]),
    ("CONTROLLED_BIT_DROPS", [1.5]),
    ("CURVE_NAMES", [None]),
]

# Values that are not numbers at all, per constant, so the type guard is
# pinned separately from the range guard: a mistyped constant has to be
# NAMED rather than raise out of the comparison it was handed to.
CHECK_MISTYPED_SETTINGS = [
    ("REPEAT", "20000"),
    ("CLOCK_READS", 1.0),
    ("WARM_UP_ROUNDS", None),
    ("MEDIAN_SE_FACTOR", "1.2533"),
    ("TRIM_PROPORTIONS", "0.05"),
    ("PREFIX_SIZES", 500),
    ("CONTROLLED_BIT_DROPS", 4),
    ("CURVE_NAMES", "NIST256p"),
]

# Settings that are each usable alone and cannot be used together, as
# ``(name, value, expected)``: the entry to replace, what to replace it
# with, and the constant the report has to blame for the pair.
CHECK_INCOHERENT_SETTINGS = [
    ("BOOTSTRAP_MAX_PAIRS", 50, "BOOTSTRAP_MAX_PAIRS"),
    ("CONTROLLED_MIN_SAMPLES", 81, "CONTROLLED_MIN_SAMPLES"),
    ("MIN_BUCKET_SAMPLES", 20001, "MIN_BUCKET_SAMPLES"),
]


def check_settings(name, value):
    """`CHECK_SETTINGS` with one entry replaced.

    Copied rather than mutated, so the checks are order independent and
    one broken entry cannot leak into the next check.
    """
    settings = {}
    settings.update(CHECK_SETTINGS)
    settings[name] = value
    return settings


# Every way out of the domain a trim has to lie in, for the refusals the
# resampler owes a reader a note about.  Held in one list so a new way
# out cannot be added to `is_trim_proportion()` without a check for it:
# below zero, at the half, past the half, the whole sample, and the three
# values that are not numbers at all.  ``None`` is in there because a
# constant left unset is a likelier edit than an infinity is.
CHECK_BAD_TRIMS = [
    CHECK_BAD_TRIM,
    -1.0,
    0.5,
    0.6,
    1.0,
    float("nan"),
    float("inf"),
    float("-inf"),
    None,
]

# Trims for the resampling that RUNS.  Fixed here rather than read from
# TRIM_PROPORTIONS, like every other fixture in this section, so that
# retuning the report's estimators cannot move the labels these checks
# assert.  Two of them, and distinct, so that one interval per trim is a
# claim with something to fail on.
CHECK_TRIMS = [0.05, 0.45]

# Paired rows for that resampling.  This ONE fixture size is derived
# from a live constant rather than pinned, and the exception is
# deliberate: ``BOOTSTRAP_MIN_SAMPLES`` is `bootstrap_test()`'s own
# bound on what it will resample, so a pinned size would stop reaching
# the resampling at all if that constant were raised -- and the success
# path is precisely what has to be exercised.  One row past the floor
# reaches it at the smallest cost, and the floor itself is checked
# alongside as the boundary it is.
CHECK_BOOTSTRAP_PAIRS = BOOTSTRAP_MIN_SAMPLES + 1

# The other bound of the same function, derived for the same reason: one
# row past ``BOOTSTRAP_MAX_PAIRS`` is the smallest sample that is longer
# than the prefix actually resampled, and it is what the ``used`` column
# is checked against -- a column reporting the rows OFFERED where fewer
# were drawn would overstate the evidence behind the interval.  A run at
# the default REPEAT does reach this cap in Mode 2, so it is not a
# hypothetical.
CHECK_CAPPED_PAIRS = BOOTSTRAP_MAX_PAIRS + 1

# The three flat samples the interval endpoints are asserted to the exact
# float against: one difference repeated, positive, negative and zero.
# A sample with no spread has the same multiset in every resample, so
# every trimmed mean of it is that difference and both endpoints are
# that difference, whatever the resampler drew.  Hard-coding endpoints
# from a VARIED sample would instead pin the draw order of the Mersenne
# Twister, which `random.randrange` walks differently on Python 2 than on
# Python 3, and this script runs on both.
CHECK_FLAT_DIFFERENCE = 100.0

# The bounds every synthetic dataset below is analysed under, and the
# seed its batteries are drawn with.  Pinned here for the same reason
# CHECK_PAIRS is pinned rather than read from MIN_BUCKET_SAMPLES, and
# stated once for the four remaining tunables: MAX_PAIR_GAP,
# MAX_TESTED_BUCKETS, PREFIX_SIZES and ALPHA.
#
# A run that retunes any of those is asking for a different
# MEASUREMENT, not for different DECISION PATHS.  While the fixtures
# read the live constants, retuning one moved the fixtures out from
# under their own expected values and the failures were reported as "a
# decision path of the report is wrong" -- blaming the report for the
# configuration, and hiding a real fault behind dozens of spurious
# ones.  The report itself still reads the live constants, through the
# ``LIMITS`` bundle; only the fixtures are held still.
#
# The values equal the shipped defaults, so a default run's self check
# makes exactly the comparisons it made before this separation.  The
# ladder is the single first rung: everything past it is a claim about
# sample counts these datasets do not reach.
CHECK_GAP = 16
CHECK_MOST = 8
CHECK_PREFIX_FIRST = 500
CHECK_PREFIX_SIZES = [CHECK_PREFIX_FIRST]
CHECK_ALPHA = 1e-6
CHECK_SEED = 12345
CHECK_LIMITS = measurement_limits(
    CHECK_GAP, CHECK_MOST, CHECK_PREFIX_SIZES, CHECK_ALPHA
)

# Attempts between two parts of a dataset that must not pair with each
# other.  One past the proximity bound is enough: at that distance the
# earliest unspent reference is always further into the future than the
# bound allows, so no pair is formed across the join.
CHECK_SEPARATION = CHECK_GAP + 1

# Offsets that cancel: half positive and half negative, at two
# magnitudes so the ranks the Wilcoxon test forms are not all tied.
CHECK_BALANCED_PATTERN = [1.0, -1.0, 2.0, -2.0]

# Where the unpairable remainder of each bucket sits in `check_thin()`.
# Each block starts further past everything before it than the
# proximity bound allows, and the two blocks are that far from each
# other as well, so no pair survives outside the dataset's adjacent
# head.
CHECK_FAR = 2 * CHECK_PAIRS + CHECK_SEPARATION
CHECK_FARTHER = CHECK_FAR + CHECK_PAIRS + CHECK_SEPARATION


def check(results, label, got, expected):
    """Record one comparison of *got* against *expected*.

    Appends ``(label, passed, detail)`` to *results*.  Deliberately not
    an ``assert``: see the note above this section.
    """
    if got == expected:
        results.append((label, True, ""))
    else:
        results.append((label, False, "expected %r, got %r" % (expected, got)))


def check_close(results, label, got, expected, tolerance):
    """Record one comparison of *got* against *expected*, within a bound.

    For the statistics whose last bits depend on the order a sum was
    accumulated in, where an exact comparison would fail for a reason
    that is not a fault.  *tolerance* is relative to *expected* when that
    is non-zero and absolute when it is zero, and it is always given at
    the call site rather than defaulted: a check that accepted whatever
    it was handed would pass over exactly the errors it exists to catch.

    A value that is not a number fails outright rather than being
    compared, since ``nan`` is within no tolerance of anything -- and
    ``nan != nan`` would otherwise make the subtraction below quietly
    false in both directions.
    """
    if got != got or expected != expected:
        results.append((label, False, "expected %r, got %r" % (expected, got)))
        return
    bound = tolerance
    if expected != 0.0:
        bound = tolerance * abs(expected)
    if abs(got - expected) <= bound:
        results.append((label, True, ""))
        return
    results.append(
        (
            label,
            False,
            "expected %r within %r, got %r" % (expected, tolerance, got),
        )
    )


def check_names(complaints):
    """The constant names in a `setting_problems()` answer, in order.

    So a check can pin WHICH constants were named without repeating the
    whole complaint text, which is prose and would make the check about
    the wording rather than about the decision.
    """
    names = []
    for name, _ in complaints:
        names.append(name)
    return names


def check_finite(pairs):
    """How many of the three p-value tests a dataset of *pairs* answers.

    The sign test declines at or below ``SIGN_TEST_MIN_PAIRS`` usable
    pairs, and that floor is one live tunable these fixtures cannot be
    held apart from: it is read inside `sign_test()`, several layers
    below anything a check hands in.  So the expected COUNT follows it
    instead of being written as a literal three.

    At the shipped floor of ten every dataset below clears it and all
    three tests answer.  Raising it past a dataset's pair count costs
    that dataset the sign test and nothing else, leaving two p-values --
    still enough for every state these checks distinguish, since one
    readable p-value is enough for a verdict.  Deriving the count is
    what keeps a raised floor from being reported as half a dozen wrong
    decision paths in the report.
    """
    if pairs <= SIGN_TEST_MIN_PAIRS:
        return 2
    return 3


def check_row(results, label, row, expected):
    """Check one scan row against its four expected states.

    *expected* is ``(tested, finite_p, verdict, outcome)``.  The
    evidence flag is checked against the p-value count rather than
    supplied, since it is that count's only meaning.
    """
    tested, finite, verdict, outcome = expected
    check(results, label + " tested", row["tested"], tested)
    check(results, label + " finite_p", row["finite_p"], finite)
    check(results, label + " evidence", row["evidence"], finite > 0)
    check(results, label + " verdict", scan_verdict(row), verdict)
    check(results, label + " outcome", scan_outcome(row), outcome)


def check_interleaved(offsets, first_attempt=0):
    """Observations for one reference and one test bucket, pairable.

    *offsets* holds one microsecond offset per pair: the reference
    observation is that much slower than the test observation, so the
    difference `matched_differences()` computes for that pair comes out
    at approximately that value.

    The two buckets alternate at consecutive signing attempts, which is
    the arrangement the proximity matcher can pair one to one -- every
    pair is a single attempt apart and no reference is ever spent twice.
    """
    observations = []
    for index in range(len(offsets)):
        slower = CHECK_BASE_SECONDS + offsets[index] * 1e-6
        observations.append(
            (CHECK_REFERENCE_BITS, slower, first_attempt + 2 * index)
        )
        observations.append(
            (
                CHECK_TEST_BITS,
                CHECK_BASE_SECONDS,
                first_attempt + 2 * index + 1,
            )
        )
    return observations


def check_flat(bits, count, first_attempt):
    """*count* observations of one bucket width, at consecutive attempts.

    Every duration is identical, so this builder is for the datasets
    whose point is which buckets exist rather than what they hold.
    """
    observations = []
    for index in range(count):
        observations.append((bits, CHECK_BASE_SECONDS, first_attempt + index))
    return observations


def check_round_matched():
    """Three buckets and their rounds, as Mode 1's collection leaves them.

    Returns ``(buckets, rounds)`` -- the pair of dicts `battery_entries()`
    takes when there are no recovered observations to proximity-match,
    which is the interleaved Mode 1 case.  Every bucket holds the same
    rounds, so every observation pairs, and the three durations differ by
    a constant so the differences are non-zero.
    """
    widths = [CHECK_REFERENCE_BITS, CHECK_TEST_BITS, CHECK_OTHER_BITS]
    buckets = {}
    rounds = {}
    for index in range(len(widths)):
        seconds = CHECK_BASE_SECONDS * (1.0 - 0.1 * index)
        buckets[widths[index]] = [seconds] * CHECK_PAIRS
        rounds[widths[index]] = list(range(CHECK_PAIRS))
    return (buckets, rounds)


def check_tested(entries):
    """How many of *entries* carry a battery that actually ran."""
    total = 0
    for _, result in entries:
        if result["tested"]:
            total += 1
    return total


def check_sizes(rows):
    """The prefix size of every scan row, in order.

    A whole list compared at once, so a check about which prefixes were
    walked neither indexes a row that may not be there nor raises out of
    the self check when it is not -- the checks report, they do not
    interrupt.
    """
    sizes = []
    for row in rows:
        sizes.append(row["size"])
    return sizes


def check_last(rows, name):
    """Field *name* of the last scan row, or ``None`` when there are none."""
    if not rows:
        return None
    return rows[-1][name]


def check_reasons(classified):
    """Just the reasons of a `classified_widths()` answer, in order."""
    reasons = []
    for _, reason in classified:
        reasons.append(reason)
    return reasons


def check_refused_bits(order, drops, floor):
    """Just the bit widths `refused_widths()` names, in order."""
    named = []
    for bits, _ in refused_widths(order, drops, floor):
        named.append(bits)
    return named


def check_width_tally(order):
    """``(supplied, refused, duplicated, asked)`` for the live drop list.

    A partition: every width the configuration asks for is either one
    this curve can supply, one it cannot and that is therefore named, or
    a repeat of one already asked for.  Counted rather than listed so the
    claim holds whatever ``CONTROLLED_BIT_DROPS`` is retuned to -- the
    exact classifications are pinned against a fixed drop list instead.
    """
    classified = classified_widths(order)
    duplicated = 0
    for _, reason in classified:
        if reason == WIDTH_DUPLICATE:
            duplicated += 1
    return (
        len(controlled_widths(order)),
        len(refused_widths(order)),
        duplicated,
        len(classified),
    )


def check_width_agreement(order, drops, floor, rnd):
    """``(disagreements, examined)`` between the predicate and a draw.

    For every width `classified_widths()` accounts for, other than a
    repeat, this compares what `width_is_supplyable()` predicted against
    what `nonce_of_bit_length()` actually returns, and reports the widths
    where the two differ as ``(bits, predicted, observed)``.  That is the
    only oracle available for the classification which does not repeat
    the classifier's own reasoning: the predicate decides from an
    interval's emptiness, the draw decides by drawing from it.

    A drawn nonce whose bit length is not the width asked for counts as a
    disagreement too.  "Supplyable" has to mean a nonce of EXACTLY this
    width, not merely that something came back, because the buckets a
    Mode 1 table compares are bit widths.

    A non-positive width is predicted-only: it is refused by the
    predicate and never reaches the draw, whose ``1 << (bits - 1)`` would
    raise for it.  The live drop list does ask for such widths -- a drop
    of 192 against a 161-bit order is -31 bits -- so this is the ordinary
    case for a small curve rather than a defensive one.

    *examined* is returned alongside so a caller can state how many
    widths the agreement covers, instead of only that nothing disagreed.
    """
    disagreements = []
    examined = 0
    for bits, reason in classified_widths(order, drops, floor):
        if reason == WIDTH_DUPLICATE:
            continue
        examined += 1
        predicted = width_is_supplyable(bits, order)
        if bits < 1:
            if predicted:
                disagreements.append((bits, predicted, "not drawable"))
            continue
        drawn = nonce_of_bit_length(rnd, bits, order)
        if predicted != (drawn is not None):
            disagreements.append((bits, predicted, drawn))
        elif drawn is not None and bit_length(drawn) != bits:
            disagreements.append((bits, predicted, bit_length(drawn)))
    return (disagreements, examined)


def check_registry_agreement(rnd):
    """`check_width_agreement()` over every registered curve.

    ``(disagreements, examined, duplicated, curves_seen)`` under the LIVE
    drop list and floor, because the widths a real run asks of a real
    curve are the ones that matter.  Every one of the 26 registered
    orders is odd, so none of them can reach the refusal a power of two
    reaches -- which is why this sweep and the synthetic fixture are both
    needed, and neither replaces the other.

    ``int()`` on the order for the same reason `mul_add` coerces in the
    library: with gmpy2 installed the order is an ``mpz``, and the
    comparisons and shifts below are cheaper on a native integer.
    """
    disagreements = []
    examined = 0
    duplicated = 0
    seen = 0
    for candidate in curves:
        order = int(candidate.order)
        found, count = check_width_agreement(
            order, CONTROLLED_BIT_DROPS, MIN_NONCE_BITS, rnd
        )
        for entry in found:
            disagreements.append((candidate.name, entry))
        examined += count
        for _, reason in classified_widths(order):
            if reason == WIDTH_DUPLICATE:
                duplicated += 1
        seen += 1
    return (disagreements, examined, duplicated, seen)


def check_reason_of(entries, bits):
    """The decline reason recorded against one bucket width.

    ``None`` when that width was tested, or is not there at all, so a
    check about WHY a bucket was passed over cannot pass by accident on
    entries that do not hold it.
    """
    for width, result in entries:
        if width == bits and not result["tested"]:
            return result["reason"]
    return None


def check_spoken(rows):
    """The spoken test names of a `declined_tests()` answer, in order."""
    spoken = []
    for name, _, _ in rows:
        spoken.append(name)
    return spoken


def check_note_for(rows, spoken):
    """The note a `declined_tests()` answer carries for one test name."""
    for name, note, _ in rows:
        if name == spoken:
            return note
    return None


def check_declined_widths(rows):
    """The bucket-width list of every decline row, in order.

    Both decline answers put the widths last, so one accessor reads
    either, and a whole list is compared at once rather than indexed.
    """
    widths = []
    for row in rows:
        widths.append(row[-1])
    return widths


def check_interval_free(differences, proportions):
    """A battery over *differences*, resampled under *proportions*.

    A real battery with its bootstrap redone under a fixed proportion
    list rather than the live one, so the reasons a resampling declines
    can be exercised without retuning ``TRIM_PROPORTIONS`` -- including
    the reason that names that very constant.
    """
    result = run_battery(differences, CHECK_SEED)
    result["bootstrap"] = bootstrap_test(
        differences, random.Random(CHECK_SEED), proportions
    )
    return result


def check_with_intervals(result):
    """*result* with one interval installed in its bootstrap.

    The interval's numbers are irrelevant here: `declined_intervals()`
    reads only whether there IS one, so the interval is installed rather
    than resampled, which keeps the check that a resampling which ran is
    NOT named independent of every bootstrap tunable -- the sample floor,
    the resample count and the row cap alike.  Its four fields are the
    four `bootstrap_test()` builds and `print_bootstrap()` reads, so the
    shape is the real one.  Copied rather than mutated in place so the
    battery it came from is left as its own checks found it.
    """
    filled = {}
    filled.update(result)
    bootstrap = {}
    bootstrap.update(result["bootstrap"])
    bootstrap["intervals"] = [
        {"trim": 0.05, "low": -1.0, "high": 1.0, "excludes_zero": False}
    ]
    filled["bootstrap"] = bootstrap
    return filled


def check_short_buckets():
    """One bucket at the floor and one below it, with their rounds.

    The contrast to `check_round_matched()`: there the buckets are all
    full and only the cap can turn one down, here one is genuinely too
    small, so the two reasons a bucket is passed over can be told apart.
    """
    buckets = {
        CHECK_REFERENCE_BITS: [CHECK_BASE_SECONDS] * CHECK_PAIRS,
        CHECK_TEST_BITS: [CHECK_BASE_SECONDS] * (CHECK_MINIMUM - 1),
    }
    rounds = {
        CHECK_REFERENCE_BITS: list(range(CHECK_PAIRS)),
        CHECK_TEST_BITS: list(range(CHECK_MINIMUM - 1)),
    }
    return (buckets, rounds)


def check_thin(close):
    """Two testable buckets whose observations mostly cannot be paired.

    The first *close* observations of each bucket alternate at
    consecutive attempts and pair one to one; the remainder of both sits
    beyond the proximity bound from everything before it and from each
    other, so no further pair survives.

    Both buckets still clear the testable floor, so a battery RUNS.  At
    one surviving pair every test in it declines for want of data, which
    is the all-declined battery in its purest form -- tested, valid, and
    empty of evidence -- and at two the sign test still declines while
    the other two produce numbers, which is why evidence is counted per
    readable p-value rather than per battery that ran.
    """
    observations = []
    for index in range(close):
        slower = CHECK_BASE_SECONDS + (index + 1) * 1e-6
        observations.append((CHECK_REFERENCE_BITS, slower, 2 * index))
        observations.append(
            (CHECK_TEST_BITS, CHECK_BASE_SECONDS, 2 * index + 1)
        )
    for index in range(CHECK_PAIRS - close):
        observations.append(
            (CHECK_REFERENCE_BITS, CHECK_BASE_SECONDS, CHECK_FAR + index)
        )
    for index in range(CHECK_PAIRS - close):
        observations.append(
            (CHECK_TEST_BITS, CHECK_BASE_SECONDS, CHECK_FARTHER + index)
        )
    return observations


def check_rejecting_offsets(count):
    """Offsets whose every paired difference is positive.

    All-positive differences give the sign test an exact two-sided
    binomial p of ``2 / 2**count``, which at the default thirty-two
    pairs is 4.66e-10 and so below the 1e-6 corrected alpha of a single
    comparison.  They are not all equal, so the paired t-test has a
    non-zero standard deviation to divide by and produces a number too.
    """
    offsets = []
    for index in range(count):
        offsets.append(100.0 + 0.5 * index)
    return offsets


def check_flat_differences(count, value):
    """*count* paired differences, every one of them *value*.

    The fixture that makes a bootstrap interval assertable to the exact
    float: with no spread in the sample, every resample of it is the same
    multiset, so every trimmed mean is *value* at every trim and both
    quantiles of those statistics are *value* too.  What the resampler
    drew therefore does not enter the answer, which is the property a
    varied sample cannot offer across two interpreter generations.
    """
    return [value] * count


class CheckFixedDraws(object):
    """A stand-in resampler whose draws are fixed rather than random.

    `bootstrap_test()` consumes its randomness through exactly one call,
    ``randrange(size)``, so a stand-in for it makes the resampling
    deterministic on every interpreter -- which a seeded
    ``random.Random`` cannot be, because Python 2 and Python 3 walk the
    Mersenne Twister differently for the same seed.

    *stride* chooses which of two fixed patterns is drawn, and the two
    together are a pair of oracles rather than one:

    * ``1`` walks the rows in turn, so every resample is the sample
      rearranged and every statistic is the trimmed mean of the sample
      itself -- a number `trimmed_mean_sorted()` supplies independently.
      That checks the whole chain from a draw to an endpoint: resample,
      sort, trim, quantile;
    * ``0`` draws the first row every time, so every resample is that one
      row repeated and both endpoints are that row's own value.  That
      checks the draw is CONSULTED, which the first pattern cannot: a
      resampling that ignored its resampler and took the sample as it
      stands would satisfy the first oracle exactly.
    """

    def __init__(self, stride):
        self.stride = stride
        self.calls = 0

    def randrange(self, size):
        """The next fixed index for a sample of *size* rows."""
        index = (self.calls * self.stride) % size
        self.calls += 1
        return index


def check_bootstrap_offsets():
    """Varied differences, enough of them for the resampling to run.

    Ascending and all positive, so two independent things follow without
    depending on the draw: every trimmed mean of every resample lies
    between the smallest and the largest difference, and every one of
    them is above zero -- so an interval built from them must exclude
    zero.  Used for the claims about a resampling's shape that a flat
    sample cannot make, reproducibility among them.
    """
    return check_rejecting_offsets(CHECK_BOOTSTRAP_PAIRS)


def check_interval_shape(result):
    """``(count, trims, used, note)`` of a bootstrap answer.

    Four of the five things `print_bootstrap()` reads, gathered so one
    comparison covers them at once instead of four that could each pass
    on a different fixture.  The endpoints are left out because they are
    asserted to the exact float separately.
    """
    trims = []
    for interval in result["intervals"]:
        trims.append(interval["trim"])
    return (len(result["intervals"]), trims, result["used"], result["note"])


def check_interval_bounds(result):
    """``(low, high, excludes_zero)`` per interval of a bootstrap answer."""
    bounds = []
    for interval in result["intervals"]:
        bounds.append(
            (interval["low"], interval["high"], interval["excludes_zero"])
        )
    return bounds


def check_intervals_within(result, low, high):
    """Whether every interval endpoint lies within ``[low, high]``.

    True of any percentile bootstrap on trimmed means, whatever it drew:
    a trimmed mean of a resample is an average of values from the sample,
    so it cannot leave the sample's range, and neither can a quantile of
    those averages.  The claim a varied fixture can make about endpoints
    without pinning the resampler's draw order.
    """
    for interval in result["intervals"]:
        if interval["low"] > interval["high"]:
            return False
        if interval["low"] < low or interval["high"] > high:
            return False
    return True


def check_running_note():
    """The note a resampling that ran carries.

    Built the way `bootstrap_test()` builds it, from the live resample
    count, because that count is printed inside the note and pinning it
    would only assert that nobody had retuned it.
    """
    return "95%% percentile interval, %d resamples" % (BOOTSTRAP_RESAMPLES,)


def check_bad_trim_note(proportion):
    """The note a trim outside the allowed domain earns."""
    return (
        "TRIM_PROPORTIONS holds %r, which is not a finite proportion "
        "below 0.5" % (proportion,)
    )


def check_boot_pairs():
    """A paired sample two rows clear of the bootstrap's own floor.

    Sized from the LIVE floor rather than from a fixed number, because
    `bootstrap_test()` reads ``BOOTSTRAP_MIN_SAMPLES`` out of module
    state: a fixture of fixed length would start being turned down for
    being too short, rather than for the cap under test, the moment
    anyone raised that floor.  Two rows clear, so that a cap AT the floor
    still leaves fewer pairs than were available and the two refusals
    stay distinguishable.
    """
    return check_rejecting_offsets(BOOTSTRAP_MIN_SAMPLES + 2)


def check_balanced_offsets(count):
    """Offsets whose differences cancel, so that nothing rejects.

    The control that proves a real "not detected" is still reachable:
    every test produces a readable number, the sign test sees half its
    pairs positive and answers 1.0, and the mean the t-test reads is
    approximately zero.
    """
    offsets = []
    for index in range(count):
        offsets.append(
            CHECK_BALANCED_PATTERN[index % len(CHECK_BALANCED_PATTERN)]
        )
    return offsets


def check_entries(observations):
    """The full-sample battery for *observations*, as a mode would run it.

    Bucketed, reference chosen and paired exactly as `report_mode()`
    does for Mode 2, so the entries the checks below inspect are the
    ones a real run would hand to `print_detection()` and to
    `scan_prefixes()`.
    """
    buckets = bucket_prefix(observations, len(observations))
    reference_bits = reference_bit_length(buckets)
    return battery_entries(
        buckets,
        reference_bits,
        CHECK_MINIMUM,
        CHECK_SEED,
        observations,
        None,
        CHECK_LIMITS,
    )


def check_scan(observations, full_entries=None):
    """`scan_prefixes()` over *observations*, under the check's bounds.

    Every self-check scan goes through here, so that not one of them
    reads the live prefix ladder, proximity bound, bucket cap or alpha.
    An empty ``PREFIX_SIZES`` used to raise ``IndexError`` out of a
    fixture that indexed it directly; a retuned ladder, gap, cap or
    alpha used to move dozens of these checks off their expected values.
    Neither can happen through this door.
    """
    return scan_prefixes(
        observations, CHECK_MINIMUM, full_entries, CHECK_LIMITS
    )


def self_check_without_evidence(results):
    """Scans that produced no p-value at all must report insufficient.

    Four ways to get there, all of which used to be reported as
    "not detected at N <= ..." with a recorded outcome of ``no``: no
    observation whatsoever, one populated bucket with nothing to compare
    against it, a comparison bucket below the testable floor, and a
    comparison bucket above the floor whose observations are all too far
    from the reference bucket's to be paired.
    """

    # the properties the datasets below rely on, checked rather than
    # asserted in a comment
    check(
        results,
        "pairs divide the balanced pattern",
        CHECK_PAIRS % len(CHECK_BALANCED_PATTERN),
        0,
    )
    # CHECK_FINITE claims how many p-values a dataset of this size can
    # carry under the live sign-test floor.  Checked against a real
    # battery, and against the direction of the floor's own decision, so
    # that the derivation is verified rather than trusted.
    sample = check_entries(
        check_interleaved(check_rejecting_offsets(CHECK_PAIRS))
    )[0][1]
    check(
        results,
        "check datasets carry the derived p-value count",
        battery_finite_p_count(sample),
        check_finite(CHECK_PAIRS),
    )
    check(
        results,
        "the sign test declines only at or below its floor",
        sample["sign"]["p"] is None,
        CHECK_PAIRS <= SIGN_TEST_MIN_PAIRS,
    )
    # the derivation's boundary, which is `sign_test()`'s own: it needs
    # MORE than SIGN_TEST_MIN_PAIRS usable pairs, so a dataset holding
    # exactly that many loses the third p-value
    check(
        results,
        "the derived count drops at the floor",
        check_finite(SIGN_TEST_MIN_PAIRS),
        2,
    )
    check(
        results,
        "the derived count rises one past the floor",
        check_finite(SIGN_TEST_MIN_PAIRS + 1),
        3,
    )

    detected_at, rows = check_scan([])
    check(results, "empty rows", rows, [])
    check(results, "empty detected_at", detected_at, None)
    check(results, "empty tested sizes", scan_tested_sizes(rows), [])
    check(results, "empty evidence", scan_has_evidence(rows), False)
    check(
        results,
        "empty headline",
        scan_headline(detected_at, rows),
        "insufficient",
    )

    lone = check_flat(CHECK_REFERENCE_BITS, CHECK_PAIRS, 0)
    detected_at, rows = check_scan(lone)
    check(results, "lone bucket rows", len(rows), 1)
    check(results, "lone bucket size", rows[0]["size"], CHECK_PAIRS)
    check(
        results,
        "lone bucket reference",
        rows[0]["reference"],
        CHECK_REFERENCE_BITS,
    )
    check(results, "lone bucket valid", rows[0]["valid"], True)
    check(results, "lone bucket min_p", rows[0]["min_p"], None)
    check_row(
        results, "lone bucket", rows[0], (0, 0, "no data", "insufficient")
    )
    check(
        results,
        "lone bucket headline",
        scan_headline(detected_at, rows),
        "insufficient",
    )

    small = lone + check_flat(CHECK_TEST_BITS, 5, CHECK_PAIRS)
    detected_at, rows = check_scan(small)
    check(results, "small bucket rows", len(rows), 1)
    check(results, "small bucket size", rows[0]["size"], CHECK_PAIRS + 5)
    check_row(
        results, "small bucket", rows[0], (0, 0, "no data", "insufficient")
    )
    check(
        results,
        "small bucket headline",
        scan_headline(detected_at, rows),
        "insufficient",
    )

    apart = lone + check_flat(
        CHECK_TEST_BITS, CHECK_PAIRS, CHECK_PAIRS + CHECK_SEPARATION
    )
    detected_at, rows = check_scan(apart)
    check(results, "unpairable rows", len(rows), 1)
    # the bucket IS testable -- it clears the floor -- and still yields
    # nothing, which is the case a count of testable buckets alone would
    # have read as evidence
    check_row(
        results, "unpairable", rows[0], (1, 0, "no data", "insufficient")
    )
    check(results, "unpairable detected_at", detected_at, None)
    check(
        results,
        "unpairable headline",
        scan_headline(detected_at, rows),
        "insufficient",
    )
    check(results, "unpairable tested sizes", scan_tested_sizes(rows), [])


def self_check_with_evidence(results):
    """A battery that ran must still be able to say all three things.

    The counterpart to the checks above: the insufficient state must not
    have swallowed the two states that are results, nor the one that
    withdraws them.
    """
    pairs = CHECK_PAIRS
    total = 2 * pairs

    rejecting = check_interleaved(check_rejecting_offsets(pairs))
    detected_at, rows = check_scan(rejecting)
    check(results, "rejecting rows", len(rows), 1)
    check(results, "rejecting size", rows[0]["size"], total)
    check_row(
        results,
        "rejecting",
        rows[0],
        (1, check_finite(pairs), "detected", "yes"),
    )
    check(results, "rejecting detected_at", detected_at, total)
    check(
        results, "rejecting headline", scan_headline(detected_at, rows), total
    )
    check(results, "rejecting tested sizes", scan_tested_sizes(rows), [total])

    balanced = check_interleaved(check_balanced_offsets(pairs))
    detected_at, rows = check_scan(balanced)
    check(results, "balanced rows", len(rows), 1)
    check_row(
        results, "balanced", rows[0], (1, check_finite(pairs), "-", "no")
    )
    check(results, "balanced detected_at", detected_at, None)
    check(
        results, "balanced headline", scan_headline(detected_at, rows), "none"
    )
    check(results, "balanced tested sizes", scan_tested_sizes(rows), [total])

    unreadable = check_interleaved(check_rejecting_offsets(pairs))
    unreadable[1] = (
        CHECK_TEST_BITS,
        float("inf"),
        unreadable[1][2],
    )
    detected_at, rows = check_scan(unreadable)
    check(results, "unreadable rows", len(rows), 1)
    check(results, "unreadable valid", rows[0]["valid"], False)
    check_row(results, "unreadable", rows[0], (1, 0, "invalid", "invalid"))
    check(results, "unreadable detected_at", detected_at, None)
    check(
        results,
        "unreadable headline",
        scan_headline(detected_at, rows),
        "invalid",
    )
    check(results, "unreadable tested sizes", scan_tested_sizes(rows), [])


def self_check_prefix_ladder(results):
    """A bound may only be read from the prefixes a test ran over.

    Two ladders where some prefix produced evidence and some did not.
    The first gains its comparison late, so the bound is the whole
    sample and the earlier prefix is merely excluded from it.  The second
    loses it late -- a wider bucket appears too far from everything
    already collected to pair with any of it, and becomes the reference
    -- so the bound stops short of the observation count, which is the
    case that would otherwise print a nondetection over a prefix in
    which nothing was compared.

    Both datasets are sized around ``CHECK_PREFIX_FIRST``, the ladder
    the checks run under, rather than around whatever the live
    ``PREFIX_SIZES`` begins with.  Indexing the live list here meant an
    empty ladder -- a legitimate edit, since the scan tests the full
    sample regardless -- raised ``IndexError`` out of the self check
    instead of running it.
    """
    first = CHECK_PREFIX_FIRST

    late = check_flat(CHECK_OTHER_BITS, first, 0) + check_interleaved(
        check_balanced_offsets(CHECK_PAIRS), first + CHECK_SEPARATION
    )
    late_total = first + 2 * CHECK_PAIRS
    detected_at, rows = check_scan(late)
    check(results, "late rows", len(rows), 2)
    check(results, "late first size", rows[0]["size"], first)
    check(
        results, "late first reference", rows[0]["reference"], CHECK_OTHER_BITS
    )
    check_row(
        results, "late first", rows[0], (0, 0, "no data", "insufficient")
    )
    check(results, "late last size", rows[1]["size"], late_total)
    check(
        results,
        "late last reference",
        rows[1]["reference"],
        CHECK_REFERENCE_BITS,
    )
    check(results, "late last comparisons", rows[1]["comparisons"], 2)
    check_row(
        results,
        "late last",
        rows[1],
        (2, check_finite(CHECK_PAIRS), "-", "no"),
    )
    check(results, "late detected_at", detected_at, None)
    check(results, "late headline", scan_headline(detected_at, rows), "none")
    check(results, "late tested sizes", scan_tested_sizes(rows), [late_total])

    early = check_interleaved(check_balanced_offsets(first // 2)) + check_flat(
        CHECK_WIDER_BITS, 40, first + CHECK_SEPARATION
    )
    early_total = first + 40
    detected_at, rows = check_scan(early)
    check(results, "early rows", len(rows), 2)
    check(results, "early first size", rows[0]["size"], first)
    check_row(
        results,
        "early first",
        rows[0],
        (1, check_finite(first // 2), "-", "no"),
    )
    check(results, "early last size", rows[1]["size"], early_total)
    check(
        results, "early last reference", rows[1]["reference"], CHECK_WIDER_BITS
    )
    check_row(
        results, "early last", rows[1], (2, 0, "no data", "insufficient")
    )
    check(results, "early detected_at", detected_at, None)
    check(results, "early headline", scan_headline(detected_at, rows), "none")
    check(results, "early tested sizes", scan_tested_sizes(rows), [first])
    # the bound the report prints is the largest TESTED prefix, which
    # here is short of the sample count by every observation in the
    # prefix that tested nothing
    check(results, "early bound below total", first < early_total, True)


def self_check_thin_battery(results):
    """A battery that ran and produced nothing is still not a result.

    The two cases either side of the line.  With one surviving pair every
    test declines and the mode has no evidence at all, even though a
    battery was run over a bucket that cleared the floor -- which is why
    the count of testable buckets cannot stand in for evidence.  With
    two, at least two tests answer and one readable p-value is enough:
    the verdict becomes a real one.  How many answer at two pairs is
    ``check_finite(2)``, since whether the sign test is among them is
    ``SIGN_TEST_MIN_PAIRS``'s to decide and both ways are legitimate
    settings.
    """

    entries = check_entries(check_thin(1))
    check(results, "thin one entries", len(entries), 1)
    result = entries[0][1]
    check(results, "thin one pairs", result["pairs"], 1)
    check(results, "thin one ran", result["tested"], True)
    check(results, "thin one valid", battery_is_valid(result), True)
    check(results, "thin one finite", battery_finite_p_count(result), 0)
    check(
        results,
        "thin one state",
        detection_state(entries, CHECK_ALPHA),
        "insufficient",
    )
    detected_at, rows = check_scan(check_thin(1))
    check(results, "thin one rows", len(rows), 1)
    check_row(results, "thin one", rows[0], (1, 0, "no data", "insufficient"))
    check(
        results,
        "thin one headline",
        scan_headline(detected_at, rows),
        "insufficient",
    )

    entries = check_entries(check_thin(2))
    result = entries[0][1]
    check(results, "thin two pairs", result["pairs"], 2)
    check(
        results,
        "thin two sign readable",
        result["sign"]["p"] is not None,
        check_finite(2) == 3,
    )
    check(
        results,
        "thin two finite",
        battery_finite_p_count(result),
        check_finite(2),
    )
    check(
        results,
        "thin two state",
        detection_state(entries, CHECK_ALPHA),
        "not detected",
    )
    detected_at, rows = check_scan(check_thin(2))
    check_row(results, "thin two", rows[0], (1, check_finite(2), "-", "no"))
    check(
        results, "thin two headline", scan_headline(detected_at, rows), "none"
    )


def check_state_row(valid, evidence, rejected):
    """A scan row carrying only the three fields a verdict is read from."""
    return {"valid": valid, "evidence": evidence, "rejected": rejected}


def self_check_verdict_states(results):
    """Which guard wins, over every combination of the three flags.

    Built by hand rather than measured, so that the order the states are
    decided in is pinned rather than inferred from whichever combination
    a dataset happened to produce.  Validity outranks evidence and
    evidence outranks rejection, because each is a statement about
    whether the next one can be read at all.
    """
    cases = [
        ("invalid over rejection", False, True, True, "invalid", "invalid"),
        ("invalid alone", False, False, False, "invalid", "invalid"),
        (
            "no evidence over rejection",
            True,
            False,
            True,
            "no data",
            "insufficient",
        ),
        ("no evidence", True, False, False, "no data", "insufficient"),
        ("rejection", True, True, True, "detected", "yes"),
        ("no rejection", True, True, False, "-", "no"),
    ]
    for label, valid, evidence, rejected, verdict, outcome in cases:
        row = check_state_row(valid, evidence, rejected)
        check(results, label + " verdict", scan_verdict(row), verdict)
        check(results, label + " outcome", scan_outcome(row), outcome)

    unreadable = check_state_row(False, True, True)
    empty = check_state_row(True, False, False)
    tested = check_state_row(True, True, False)
    unreadable["size"] = 1
    empty["size"] = 2
    tested["size"] = 3
    check(
        results,
        "tested sizes skip the rest",
        scan_tested_sizes([unreadable, empty, tested]),
        [3],
    )
    check(
        results,
        "invalid outranks a detection",
        scan_headline(3, [unreadable, tested]),
        "invalid",
    )
    # a detected_at can only come from a row that produced a p-value, so
    # this pairing cannot arise from `scan_prefixes()`; it is checked to
    # pin the precedence rather than because it is reachable
    check(
        results,
        "no evidence outranks a detection",
        scan_headline(2, [empty]),
        "insufficient",
    )
    check(
        results, "evidence reaches a detection", scan_headline(3, [tested]), 3
    )
    check(
        results, "evidence reaches none", scan_headline(None, [tested]), "none"
    )


def self_check_detection_states(results):
    """The Mode 1 and Mode 2 verdict, over the same synthetic batteries.

    `print_detection()` reads one number, the smallest p-value across
    the mode's buckets, and that number is ``None`` both for a mode
    whose buckets all declined and -- necessarily -- for a mode with no
    buckets at all.  ``None`` compares false against every threshold, so
    the state has to be decided before the comparison rather than by it.
    """
    check(results, "no entries valid", batteries_are_valid([]), True)
    check(results, "no entries finite", entries_finite_p_count([]), 0)
    check(
        results,
        "no entries state",
        detection_state([], CHECK_ALPHA),
        "insufficient",
    )

    declined = declined_battery(0, "declined for the test")
    check(results, "declined finite", battery_finite_p_count(declined), 0)
    check(results, "declined valid", battery_is_valid(declined), True)
    unreadable = declined_battery(4, NON_FINITE_NOTE, valid=False)
    check(results, "unreadable finite", battery_finite_p_count(unreadable), 0)
    check(results, "unreadable valid", battery_is_valid(unreadable), False)

    lone = check_flat(CHECK_REFERENCE_BITS, CHECK_PAIRS, 0)
    small = check_entries(lone + check_flat(CHECK_TEST_BITS, 5, CHECK_PAIRS))
    check(results, "small entries", len(small), 1)
    check(results, "small entries finite", entries_finite_p_count(small), 0)
    check(results, "small entries valid", batteries_are_valid(small), True)
    check(
        results,
        "small entries minimum",
        entries_minimum_p(small),
        (None, "-", None),
    )
    check(
        results,
        "small entries state",
        detection_state(small, CHECK_ALPHA),
        "insufficient",
    )
    check(
        results,
        "small entries reason",
        small[0][1]["reason"],
        "holds fewer than %d observations" % (CHECK_MINIMUM,),
    )

    apart = check_entries(
        lone
        + check_flat(
            CHECK_TEST_BITS, CHECK_PAIRS, CHECK_PAIRS + CHECK_SEPARATION
        )
    )
    check(results, "apart entries finite", entries_finite_p_count(apart), 0)
    check(
        results,
        "apart entries state",
        detection_state(apart, CHECK_ALPHA),
        "insufficient",
    )
    check(
        results,
        "apart entries reason",
        apart[0][1]["reason"],
        "no pair within %d signing attempts" % (CHECK_GAP,),
    )

    rejecting = check_entries(
        check_interleaved(check_rejecting_offsets(CHECK_PAIRS))
    )
    check(
        results,
        "rejecting entries finite",
        entries_finite_p_count(rejecting),
        check_finite(CHECK_PAIRS),
    )
    check(
        results,
        "rejecting entries state",
        detection_state(rejecting, CHECK_ALPHA),
        "detected",
    )

    balanced = check_entries(
        check_interleaved(check_balanced_offsets(CHECK_PAIRS))
    )
    check(
        results,
        "balanced entries finite",
        entries_finite_p_count(balanced),
        check_finite(CHECK_PAIRS),
    )
    check(
        results,
        "balanced entries state",
        detection_state(balanced, CHECK_ALPHA),
        "not detected",
    )
    # the same battery against a threshold no p-value can clear, to show
    # the threshold is read rather than the state being fixed by the data
    check(
        results,
        "balanced entries at a loose threshold",
        detection_state(balanced, 2.0),
        "detected",
    )

    observations = check_interleaved(check_rejecting_offsets(CHECK_PAIRS))
    observations[1] = (CHECK_TEST_BITS, float("inf"), observations[1][2])
    unusable = check_entries(observations)
    check(
        results, "unusable entries finite", entries_finite_p_count(unusable), 0
    )
    check(
        results, "unusable entries valid", batteries_are_valid(unusable), False
    )
    check(
        results,
        "unusable entries state",
        detection_state(unusable, CHECK_ALPHA),
        "unavailable",
    )

    # the same all-declined batteries handed to the scan as the finished
    # run's own, which is the path Mode 2 takes: the last prefix reads
    # its p-values from these rather than recomputing them, so the state
    # has to survive the handover
    detected_at, rows = check_scan(
        lone + check_flat(CHECK_TEST_BITS, 5, CHECK_PAIRS), small
    )
    check(
        results,
        "handed over headline",
        scan_headline(detected_at, rows),
        "insufficient",
    )
    check(results, "handed over finite", rows[-1]["finite_p"], 0)
    detected_at, rows = check_scan(
        check_interleaved(check_balanced_offsets(CHECK_PAIRS)), balanced
    )
    check(
        results,
        "handed over evidence headline",
        scan_headline(detected_at, rows),
        "none",
    )
    check(
        results,
        "handed over evidence finite",
        rows[-1]["finite_p"],
        check_finite(CHECK_PAIRS),
    )


def self_check_report_status(results):
    """A mode that compared nothing must not reach ``EXIT_REPORTED``.

    The states each mode can end in, carried through to the status a
    caller reads.  The case this exists for is the one in the middle of
    the table below: a run in which nothing went WRONG -- no refused
    signature, no unconfirmed nonce, no missing curve, so nothing to
    record as a problem -- and in which a mode nevertheless carried out
    no comparison at all, because every bucket it had sat below the
    testable floor.  Reading the status off the problem list alone
    reported that run as evidence, and the validity section said in
    words that a comparison had been produced.  Both now come from the
    registry instead, and both are pinned here.

    Written against synthetic registries rather than by staging a
    measurement: the decision is a pure function of two lists, and the
    self check runs before any signature is timed.
    """
    for state in ["detected", "not detected", "none", 500, 20000]:
        check(
            results,
            "state %r is a comparison" % (state,),
            state_is_comparison(state),
            True,
        )
    for state in NON_RESULT_STATES:
        check(
            results,
            "state %r is not a comparison" % (state,),
            state_is_comparison(state),
            False,
        )

    both = [("curve mode 1", True), ("curve mode 2", True)]
    half = [("curve mode 1", True), ("curve mode 2", False)]
    neither = [("curve mode 1", False), ("curve mode 2", False)]
    trouble = [("curve mode 2", "a reason")]

    check(results, "empty tally", evidence_tally([]), (0, 0))
    check(results, "both tally", evidence_tally(both), (2, 2))
    check(results, "half tally", evidence_tally(half), (1, 2))
    check(results, "neither tally", evidence_tally(neither), (0, 2))

    check(results, "empty missing", missing_evidence([]), [])
    check(results, "both missing", missing_evidence(both), [])
    check(results, "half missing", missing_evidence(half), ["curve mode 2"])
    check(
        results,
        "neither missing",
        missing_evidence(neither),
        ["curve mode 1", "curve mode 2"],
    )

    # an empty registry is incomplete, not vacuously complete: a run that
    # asked for nothing produced nothing
    check(results, "empty incomplete", evidence_complete([]), False)
    check(results, "both complete", evidence_complete(both), True)
    check(results, "half incomplete", evidence_complete(half), False)
    check(results, "neither incomplete", evidence_complete(neither), False)

    check(
        results,
        "complete and untroubled is reported",
        report_status([], both),
        EXIT_REPORTED,
    )
    # the case QA found: nothing recorded against the run, and a mode
    # that compared nothing
    check(
        results,
        "incomplete without a problem is unavailable",
        report_status([], half),
        EXIT_UNAVAILABLE,
    )
    check(
        results,
        "nothing measured is unavailable",
        report_status([], []),
        EXIT_UNAVAILABLE,
    )
    check(
        results,
        "a problem outranks complete evidence",
        report_status(trouble, both),
        EXIT_UNAVAILABLE,
    )
    check(
        results,
        "a problem and incomplete evidence is unavailable",
        report_status(trouble, half),
        EXIT_UNAVAILABLE,
    )
    # the two statuses have to stay distinguishable, or the check above
    # would pass against an implementation that returned one of them for
    # everything
    check(
        results,
        "the two statuses differ",
        EXIT_REPORTED == EXIT_UNAVAILABLE,
        False,
    )

    # A curve the run never reached at all: the scopes it stood for are
    # registered as unproduced so the tally names the denominator the
    # configuration asked for.  The bug this pins reported "0 of 0" for a
    # run whose whole curve list was a typo, which reads as a run that
    # asked for nothing.
    check(
        results,
        "unproduced scopes are the two modes",
        unproduced_scopes("Curve"),
        ["Curve mode 1", "Curve mode 2"],
    )
    check(
        results,
        "unproduced scopes agree with the measurements",
        unproduced_scopes("Curve"),
        [mode_scope("Curve", 1), mode_scope("Curve", 2)],
    )
    check(
        results, "mode 1 scope", mode_scope("NIST256p", 1), "NIST256p mode 1"
    )
    check(
        results, "mode 2 scope", mode_scope("NIST256p", 2), "NIST256p mode 2"
    )

    unreached = []
    for unreached_name in ["missing", "Ed25519"]:
        for unreached_scope in unproduced_scopes(unreached_name):
            unreached.append((unreached_scope, False))
    check(
        results,
        "one unreached curve asks for two",
        evidence_tally(unreached[:2]),
        (0, 2),
    )
    check(
        results,
        "two unreached curves ask for four",
        evidence_tally(unreached),
        (0, 4),
    )
    check(
        results,
        "an unreached curve is not complete",
        evidence_complete(unreached),
        False,
    )
    check(
        results,
        "an unreached curve is unavailable",
        report_status([("missing", "a reason")], unreached),
        EXIT_UNAVAILABLE,
    )

    # The reason is one fact about the curve, so the backstop must not
    # restate it once per mode: a problem recorded against the curve as a
    # whole explains both of its modes.
    named = [("missing", "a reason"), ("Ed25519", "a reason")]
    check(
        results,
        "a curve problem explains both its modes",
        unexplained_scopes(named, unreached),
        [],
    )
    check(
        results,
        "an unnamed curve's modes still need a problem",
        unexplained_scopes([("missing", "a reason")], unreached),
        ["Ed25519 mode 1", "Ed25519 mode 2"],
    )
    check(
        results,
        "nothing recorded leaves every mode unexplained",
        unexplained_scopes([], unreached),
        [
            "missing mode 1",
            "missing mode 2",
            "Ed25519 mode 1",
            "Ed25519 mode 2",
        ],
    )
    check(
        results,
        "a produced mode never needs a problem",
        unexplained_scopes([], both),
        [],
    )
    check(
        results,
        "a mode's own problem explains it",
        unexplained_scopes([("curve mode 2", "a reason")], half),
        [],
    )

    # The separator has to follow the recorded scope immediately, which
    # is what stops one curve's problem reaching another curve whose
    # name it begins with, and stops a refused setting reaching a mode.
    check(
        results,
        "a scope covers itself",
        problem_covers("NIST256p mode 1", "NIST256p mode 1"),
        True,
    )
    check(
        results,
        "a curve covers its own mode",
        problem_covers("NIST256p", "NIST256p mode 1"),
        True,
    )
    check(
        results,
        "a curve does not cover a longer name's mode",
        problem_covers("NIST25", "NIST256p mode 1"),
        False,
    )
    check(
        results,
        "a curve does not cover another curve's mode",
        problem_covers("NIST384p", "NIST256p mode 1"),
        False,
    )
    check(
        results,
        "one mode does not cover the other",
        problem_covers("NIST256p mode 1", "NIST256p mode 2"),
        False,
    )
    check(
        results,
        "a refused setting covers no mode",
        problem_covers("TRIM_PROPORTIONS", "NIST256p mode 1"),
        False,
    )
    check(
        results,
        "a curve does not cover a bare curve",
        problem_covers("NIST256p", "NIST384p"),
        False,
    )


def self_check_curve_dispatch(results):
    """A curve the run asked for and never measured, still accounted for.

    The checks above pin the decision against hand-built registries; this
    pins the registry a real run would BUILD, which is the half that was
    wrong.  Two of the three kinds of curve name a driver can be given
    never reach a measurement -- one is not registered at all, one is an
    Edwards curve and ``sign_digest()`` rejects those -- and both used to
    record a problem and move on without registering either of their
    modes as unproduced.  No verdict was affected, since a recorded
    problem withholds the status on its own, but the validity section's
    denominator counted only the curves that got as far as being
    measured: a run asked for three curves could report "2 of the 2
    comparisons this run was asked for" when it had been asked for six.

    Assembled from the real `curve_dispatch()` over real registered
    names, and evaluated against LOCAL lists.  Nothing here appends to
    ``PROBLEMS``, ``EVIDENCE`` or ``CSV_ROWS``, and the last check says
    so, because a self check that recorded evidence of its own would move
    the very tally it exists to pin.
    """
    # a fixture is only a fixture if the registry agrees with it
    check(
        results,
        "the unregistered fixture really is not registered",
        find_named_curve(CHECK_MISSING_CURVE),
        None,
    )
    dispatched_state, dispatched = curve_dispatch(CHECK_RUNNABLE_CURVE)
    check(
        results,
        "a registered prime curve dispatches as runnable",
        (dispatched_state, dispatched.name),
        (CURVE_RUNNABLE, CHECK_RUNNABLE_CURVE),
    )
    dispatched_state, dispatched = curve_dispatch(CHECK_MISSING_CURVE)
    check(
        results,
        "an unregistered name dispatches as unknown, with no curve",
        (dispatched_state, dispatched),
        (CURVE_UNKNOWN, None),
    )
    dispatched_state, dispatched = curve_dispatch(CHECK_EDWARDS_CURVE)
    check(
        results,
        "a registered Edwards curve dispatches as edwards",
        (dispatched_state, dispatched.name),
        (CURVE_EDWARDS, CHECK_EDWARDS_CURVE),
    )
    # and the two skips stay distinguishable, in the report and in the
    # validity list: they are skipped for different reasons and a reader
    # acts on them differently
    check(
        results,
        "the two skips are not printed in the same words",
        skipped_curve_line(CURVE_UNKNOWN) == skipped_curve_line(CURVE_EDWARDS),
        False,
    )
    check(
        results,
        "nor explained in the same words",
        skipped_curve_note(CURVE_UNKNOWN) == skipped_curve_note(CURVE_EDWARDS),
        False,
    )

    # the scope strings every count in the report is keyed by
    check(
        results,
        "a scope names its curve and its mode",
        mode_scope(CHECK_RUNNABLE_CURVE, 1),
        "%s mode 1" % (CHECK_RUNNABLE_CURVE,),
    )
    check(
        results,
        "and a curve is asked for in every mode",
        curve_mode_scopes(CHECK_RUNNABLE_CURVE),
        [
            mode_scope(CHECK_RUNNABLE_CURVE, 1),
            mode_scope(CHECK_RUNNABLE_CURVE, 2),
        ],
    )
    check(results, "which is two of them", len(CURVE_MODES), 2)

    # the registry a run over one curve of each kind would build
    requested = [
        CHECK_RUNNABLE_CURVE,
        CHECK_MISSING_CURVE,
        CHECK_EDWARDS_CURVE,
    ]
    local_evidence = []
    local_problems = []
    for requested_name in requested:
        requested_state, _ = curve_dispatch(requested_name)
        if requested_state == CURVE_RUNNABLE:
            # the measurement itself is not staged here; what is being
            # checked is that a curve which RUNS accounts for its own two
            # modes, as `probe_curve()` does at the end of each
            for scope in curve_mode_scopes(requested_name):
                local_evidence.append((scope, True))
            continue
        for entry in skipped_curve_problems(requested_name, requested_state):
            local_problems.append(entry)
        for entry in skipped_curve_evidence(requested_name):
            local_evidence.append(entry)
    check(
        results,
        "three curves asked for is six measurements asked for",
        evidence_tally(local_evidence),
        (2, 6),
    )
    check(
        results,
        "and the four that were skipped are named as missing",
        missing_evidence(local_evidence),
        curve_mode_scopes(CHECK_MISSING_CURVE)
        + curve_mode_scopes(CHECK_EDWARDS_CURVE),
    )
    problem_scopes = []
    for scope, _ in local_problems:
        problem_scopes.append(scope)
    check(
        results,
        "the scopes recorded against them are the scopes that are missing",
        problem_scopes,
        missing_evidence(local_evidence),
    )
    check(
        results,
        "a run that skipped two of three curves is not evidence",
        report_status(local_problems, local_evidence),
        EXIT_UNAVAILABLE,
    )
    check(
        results,
        "and the one curve it did measure would have been",
        report_status([], local_evidence[: len(CURVE_MODES)]),
        EXIT_REPORTED,
    )
    check(
        results,
        "a skipped curve leaves a diffable detect record",
        skipped_curve_fields(CHECK_EDWARDS_CURVE),
        ("detect", CHECK_EDWARDS_CURVE, "insufficient", "-", "-", 0),
    )

    # and the WIRING, which is where the fault was: everything above is
    # pure, and a `note_skipped_curve()` that computed all of it and then
    # registered none of it would satisfy every check so far -- that is
    # precisely what the driver used to do.  So it is called for real
    # here, what it appended to each of the three registries is read
    # back, and the registries are then returned to the state they were
    # in.  The restoration is asserted rather than assumed, two checks
    # down.
    problems_before = len(PROBLEMS)
    evidence_before = len(EVIDENCE)
    rows_before = len(CSV_ROWS)
    note_skipped_curve(CHECK_MISSING_CURVE, CURVE_UNKNOWN)
    registered_problems = PROBLEMS[problems_before:]
    registered_evidence = EVIDENCE[evidence_before:]
    registered_rows = CSV_ROWS[rows_before:]
    del PROBLEMS[problems_before:]
    del EVIDENCE[evidence_before:]
    del CSV_ROWS[rows_before:]
    check(
        results,
        "registering a skip registers both modes as unproduced",
        registered_evidence,
        skipped_curve_evidence(CHECK_MISSING_CURVE),
    )
    check(
        results,
        "and a reason against each of those two scopes",
        registered_problems,
        skipped_curve_problems(CHECK_MISSING_CURVE, CURVE_UNKNOWN),
    )
    check(
        results,
        "and one machine readable row saying nothing was compared",
        registered_rows,
        ["detect,%s,insufficient,-,-,0" % (CHECK_MISSING_CURVE,)],
    )

    # and none of the above is left behind in the registries the run
    # itself reads: this check runs before any measurement, so all three
    # are empty here, and a self check that changed them would move the
    # very tally it exists to pin
    check(
        results,
        "the self check has recorded nothing of its own",
        (len(PROBLEMS), len(EVIDENCE), len(CSV_ROWS)),
        (0, 0, 0),
    )


def self_check_numeric_helpers(results):
    """The statistics themselves, against values computed independently.

    Everything above checks how a verdict is DECIDED; this checks the
    numbers it is decided from.  They had no coverage anywhere: the
    package's unit suite cannot import this module without starting a
    timing run, so a wrong quantile, a wrong tail probability or a
    silently mis-trimmed mean would have reached the report and been
    read as a measurement.

    Every expectation is either exact arithmetic (a median of four
    values, a rank with one tie, a binomial tail over 2**10) or a value
    obtained from an independent route -- ``math.erfc`` for the normal
    tail, the Cauchy closed form for Student's t at one degree of
    freedom, exact ``Fraction`` summation for the binomial tail the beta
    form replaces.  None of it is this script's own output recorded as an
    expectation, which would check only that the code has not changed.
    """
    # medians, including the even-length average and unsorted input
    check(results, "median of nothing", is_finite(median([])), False)
    check(results, "median of one", median([3.0]), 3.0)
    check(
        results, "median of an even sample", median([1.0, 2.0, 3.0, 4.0]), 2.5
    )
    check(
        results,
        "median sorts its input",
        median([4.0, 1.0, 3.0, 2.0, 5.0]),
        3.0,
    )

    # quantiles, linearly interpolated as numpy's default is -- the two
    # the bootstrap interval is read at, and both ends of the range
    quarters = [0.0, 1.0, 2.0, 3.0]
    check(
        results,
        "quantile of nothing",
        is_finite(quantile_sorted([], 0.5)),
        False,
    )
    check(results, "quantile of one", quantile_sorted([7.0], 0.5), 7.0)
    check(
        results, "quantile at the middle", quantile_sorted(quarters, 0.5), 1.5
    )
    check(results, "quantile at zero", quantile_sorted(quarters, 0.0), 0.0)
    check(results, "quantile at one", quantile_sorted(quarters, 1.0), 3.0)
    check_close(
        results,
        "quantile at 2.5 %",
        quantile_sorted(quarters, 0.025),
        0.075,
        1e-12,
    )
    check_close(
        results,
        "quantile at 97.5 %",
        quantile_sorted(quarters, 0.975),
        2.925,
        1e-12,
    )

    # trimmed means, including the proportion that used to return the
    # sample's upper tail as if it were a central estimate: at ten
    # observations a proportion of -0.1 made the cut -1 and the slice
    # ordered[-1:11], so the function answered 10.0 -- the LARGEST
    # observation -- and the bootstrap built an interval around it and
    # marked it as excluding zero
    ten = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0]
    skewed = [1.0, 2.0, 3.0, 4.0, 100.0]
    check(
        results,
        "trimmed mean of nothing",
        is_finite(trimmed_mean_sorted([], 0.05)),
        False,
    )
    check(
        results,
        "a negative proportion is refused",
        is_finite(trimmed_mean_sorted(ten, -0.1)),
        False,
    )
    check(
        results,
        "a proportion past the tail is refused",
        is_finite(trimmed_mean_sorted(ten, -0.5)),
        False,
    )
    check(results, "untrimmed mean", trimmed_mean_sorted(ten, 0.0), 5.5)
    check(
        results, "trimmed mean of a tenth", trimmed_mean_sorted(ten, 0.1), 5.5
    )
    check(
        results,
        "untrimmed mean of a skew",
        trimmed_mean_sorted(skewed, 0.0),
        22.0,
    )
    check(
        results,
        "trimming removes the outlier",
        trimmed_mean_sorted(skewed, 0.2),
        3.0,
    )
    check(
        results,
        "a half trim keeps the middle",
        trimmed_mean_sorted(skewed, 0.5),
        3.0,
    )
    check(
        results,
        "an emptying trim falls back to the median",
        trimmed_mean_sorted(skewed, 1.0),
        3.0,
    )

    # the estimator answers across that whole range, and the range an
    # INTERVAL may be labelled with is narrower: `is_trim_proportion()`
    # draws the line at one half, because from there up the trim empties
    # an even sample's core and the answer is the median rather than the
    # trimmed mean the label would name.  Checked here, beside the
    # estimator whose domain it describes; what `bootstrap_test()` does
    # with a proportion outside it is checked with the bootstrap.
    for good_trim in CHECK_TRIMS + [0.0, 0.4999]:
        check(
            results,
            "%r may be a trim label" % (good_trim,),
            is_trim_proportion(good_trim),
            True,
        )
    for bad_trim in CHECK_BAD_TRIMS:
        check(
            results,
            "%r may not" % (bad_trim,),
            is_trim_proportion(bad_trim),
            False,
        )
    check(
        results,
        "a trim past the half is answered with the median instead",
        trimmed_mean_sorted(skewed, 0.6),
        median(skewed),
    )
    check(
        results,
        "which is not the estimator that label would have named",
        trimmed_mean_sorted(skewed, 0.6) == trimmed_mean_sorted(skewed, 0.0),
        False,
    )
    # and nothing in the range raises: ``int(count * nan)`` raises
    # ValueError and ``int(count * inf)`` raises OverflowError, which
    # used to come out of the middle of a resampling as a traceback
    # instead of as a declined interval
    for bad_trim in [float("nan"), float("inf"), float("-inf"), None]:
        check(
            results,
            "the estimator answers no number to a trim of %r" % (bad_trim,),
            is_finite(trimmed_mean_sorted(skewed, bad_trim)),
            False,
        )

    # rank correlation and the mid-ranks it is built on
    rising = [1.0, 2.0, 3.0, 4.0]
    check(
        results,
        "rho of a rising pair",
        spearman_rho(rising, [10.0, 20.0, 30.0, 40.0]),
        1.0,
    )
    check(
        results,
        "rho of a falling pair",
        spearman_rho(rising, [40.0, 30.0, 20.0, 10.0]),
        -1.0,
    )
    check(
        results,
        "rho of a flat side",
        is_finite(spearman_rho([1.0, 2.0, 3.0], [5.0, 5.0, 5.0])),
        False,
    )
    check(
        results,
        "rho needs two points",
        is_finite(spearman_rho([1.0], [2.0])),
        False,
    )
    check(
        results,
        "rho needs equal lengths",
        is_finite(spearman_rho([1.0, 2.0], [1.0])),
        False,
    )
    # 4 / sqrt(20), by hand from the mid-ranks [1.5, 1.5, 3.5, 3.5]
    check_close(
        results,
        "rho with ties",
        spearman_rho(rising, [1.0, 1.0, 2.0, 2.0]),
        0.8944271909999159,
        1e-12,
    )
    check(results, "ranks of nothing", mid_ranks([]), [])
    check(
        results,
        "ranks without ties",
        mid_ranks([10.0, 20.0, 30.0]),
        [1.0, 2.0, 3.0],
    )
    check(
        results,
        "ranks share a tie",
        mid_ranks([5.0, 5.0, 9.0]),
        [1.5, 1.5, 3.0],
    )
    check(
        results,
        "ranks follow position, not order",
        mid_ranks([9.0, 5.0, 5.0]),
        [3.0, 1.5, 1.5],
    )

    # the normal tail, against math.erfc computed the other way round
    check(results, "the normal tail at zero", normal_two_sided_p(0.0), 1.0)
    check_close(
        results,
        "the normal tail at one sigma",
        normal_two_sided_p(1.0),
        0.31731050786291415,
        1e-12,
    )
    check(
        results,
        "the normal tail is symmetric",
        normal_two_sided_p(-1.0) == normal_two_sided_p(1.0),
        True,
    )
    # the z at which the two-sided tail is 5 %, from the other direction
    check_close(
        results,
        "the normal tail at the 5 % point",
        normal_two_sided_p(1.959963984540054),
        0.05,
        1e-12,
    )

    # Student's t: the degenerate arguments, and two values with closed
    # forms -- at one degree of freedom the distribution is Cauchy, so
    # P(|T| >= 1) is exactly one half
    check(
        results,
        "t with no degrees of freedom",
        student_t_two_sided_p(1.0, 0),
        1.0,
    )
    check(results, "t at zero", student_t_two_sided_p(0.0, 10), 1.0)
    check(
        results,
        "t of a value that is not a number",
        student_t_two_sided_p(float("nan"), 10),
        1.0,
    )
    check(
        results,
        "t of an infinite statistic",
        student_t_two_sided_p(float("inf"), 10),
        0.0,
    )
    check_close(
        results,
        "t at one degree of freedom is Cauchy",
        student_t_two_sided_p(1.0, 1),
        0.5,
        1e-12,
    )
    check_close(
        results,
        "t at the tabulated 5 % point for ten",
        student_t_two_sided_p(2.228138851986273, 10),
        0.05,
        1e-12,
    )
    check(
        results,
        "t is symmetric",
        student_t_two_sided_p(-1.0, 1) == student_t_two_sided_p(1.0, 1),
        True,
    )

    # the binomial tail.  The small cases are exact rationals over
    # 2**10: 2/1024 for a one-sided extreme, 22/1024 for one success in
    # ten, and a capped 1.0 where twice the lower tail passes one.
    check(
        results,
        "the binomial tail of no trials",
        binomial_two_sided_p(0, 0),
        (1.0, "none"),
    )
    check(
        results,
        "the binomial tail at the extreme",
        binomial_two_sided_p(0, 10),
        (0.001953125, "exact"),
    )
    check(
        results,
        "the binomial tail is symmetric",
        binomial_two_sided_p(10, 10),
        (0.001953125, "exact"),
    )
    check(
        results,
        "the binomial tail one from the extreme",
        binomial_two_sided_p(1, 10),
        (0.021484375, "exact"),
    )
    check(
        results,
        "the binomial tail at the centre is capped",
        binomial_two_sided_p(5, 10),
        (1.0, "exact"),
    )
    # past EXACT_BINOM_MAX_N the tail comes from the incomplete beta
    # function.  The expectation is the exact integer sum over 2**1100,
    # evaluated as a rational offline; the two agree to 5e-12 relative,
    # which is what makes the cheap form usable at the corrected alpha
    # this script decides against.
    beta_p, beta_method = binomial_two_sided_p(462, 1100)
    check_close(
        results,
        "the binomial tail from the beta form",
        beta_p,
        1.241505563057448e-07,
        1e-9,
    )
    check(
        results,
        "the beta form is used past the exact bound",
        beta_method,
        "beta",
    )

    # the remaining descriptive statistics, and the scale the report
    # prints beside a difference of medians
    check(results, "the mean of nothing", is_finite(mean([])), False)
    check(results, "the mean of a pair", mean([2.0, 4.0]), 3.0)
    check(results, "the deviation of nothing", sample_sd([]), 0.0)
    check(results, "the deviation of one", sample_sd([5.0]), 0.0)
    check_close(
        results,
        "the deviation of a pair",
        sample_sd([2.0, 4.0]),
        1.4142135623730951,
        1e-12,
    )
    check(
        results,
        "the median standard error needs two a side",
        is_finite(pooled_median_se([1.0], [1.0, 2.0])),
        False,
    )
    check_close(
        results,
        "the median standard error combines in quadrature",
        pooled_median_se([1.0, 2.0], [3.0, 5.0]),
        1.4012319981002435,
        1e-12,
    )

    # the ratio used for the exact binomial tail, which exists because
    # the obvious float division overflows past an exponent of 1024
    check(results, "the ratio of nothing", ratio_over_power_of_two(0, 5), 0.0)
    check(
        results, "the ratio of a negative", ratio_over_power_of_two(-3, 5), 0.0
    )
    check(
        results,
        "the ratio at exponent zero",
        ratio_over_power_of_two(1, 0),
        1.0,
    )
    check(results, "a small exact ratio", ratio_over_power_of_two(3, 2), 0.75)
    check(
        results,
        "a ratio past the float range underflows",
        ratio_over_power_of_two(1, 2000),
        0.0,
    )
    check(
        results,
        "a ratio of a thousand-bit numerator",
        ratio_over_power_of_two(2**1100, 1100),
        1.0,
    )


def self_check_limits_and_settings(results):
    """The bounds an analysis runs under, and the settings it refuses.

    Two things are pinned here.  First, that every bound is read from
    the ``LIMITS`` bundle handed in rather than from a module constant:
    that plumbing is what lets the fixtures above be analysed under
    ``CHECK_LIMITS`` while the report is analysed under the live
    settings, and a bound that quietly kept reading its constant would
    make the fixtures move whenever the constant was retuned -- which is
    the fault this separation exists to remove.  Second, the table of
    settings a run refuses to measure under, including the one setting
    that must NOT be refused.
    """
    # the prefix ladder comes from the limits, so an empty ladder costs
    # the intermediate rungs and nothing else: the full sample is still
    # tested, which is why an empty PREFIX_SIZES is a legitimate edit
    # rather than a refusal
    sample = check_interleaved(check_balanced_offsets(CHECK_PAIRS))
    total = 2 * CHECK_PAIRS
    empty_ladder = measurement_limits(CHECK_GAP, CHECK_MOST, [], CHECK_ALPHA)
    detected_at, rows = scan_prefixes(
        sample, CHECK_MINIMUM, None, empty_ladder
    )
    check(results, "an empty ladder still tests the sample", len(rows), 1)
    check(
        results,
        "an empty ladder tests all of it",
        check_sizes(rows),
        [total],
    )
    check(
        results,
        "an empty ladder still reaches a verdict",
        scan_headline(detected_at, rows),
        "none",
    )
    rung_ladder = measurement_limits(
        CHECK_GAP, CHECK_MOST, [CHECK_PAIRS], CHECK_ALPHA
    )
    detected_at, rows = scan_prefixes(sample, CHECK_MINIMUM, None, rung_ladder)
    check(results, "a ladder rung adds a prefix", len(rows), 2)
    check(
        results,
        "the ladder walks the rung then the sample",
        check_sizes(rows),
        [CHECK_PAIRS, total],
    )

    # the proximity bound comes from the limits: a dataset whose halves
    # sit one attempt further apart than CHECK_GAP allows pairs nothing
    # under CHECK_LIMITS and pairs under a bound one wider
    apart = check_flat(CHECK_REFERENCE_BITS, CHECK_PAIRS, 0) + check_flat(
        CHECK_TEST_BITS, CHECK_PAIRS, CHECK_PAIRS + CHECK_SEPARATION
    )
    check(
        results,
        "the bound refuses a distant pair",
        matched_differences(
            apart, CHECK_REFERENCE_BITS, CHECK_TEST_BITS, CHECK_LIMITS
        ),
        [],
    )
    wider = measurement_limits(
        CHECK_PAIRS + CHECK_SEPARATION,
        CHECK_MOST,
        CHECK_PREFIX_SIZES,
        CHECK_ALPHA,
    )
    # every one of the test bucket's observations finds its own
    # reference once the bound reaches across the gap, so the pair count
    # is exactly the bucket size -- an exact number rather than "some"
    check(
        results,
        "a wider bound admits every pair",
        len(
            matched_differences(
                apart, CHECK_REFERENCE_BITS, CHECK_TEST_BITS, wider
            )
        ),
        CHECK_PAIRS,
    )
    # and the same bound reaches the battery through `battery_entries()`,
    # which is the path a mode actually takes
    apart_buckets = bucket_prefix(apart, len(apart))
    narrow_entry = battery_entries(
        apart_buckets,
        CHECK_REFERENCE_BITS,
        CHECK_MINIMUM,
        CHECK_SEED,
        apart,
        None,
        CHECK_LIMITS,
    )[0][1]
    check(
        results,
        "the battery declines the distant pair",
        narrow_entry["pairs"],
        0,
    )
    check(
        results,
        "the decline names the bound it was given",
        narrow_entry["reason"],
        "no pair within %d signing attempts" % (CHECK_GAP,),
    )
    wide_entry = battery_entries(
        apart_buckets,
        CHECK_REFERENCE_BITS,
        CHECK_MINIMUM,
        CHECK_SEED,
        apart,
        None,
        wider,
    )[0][1]
    check(
        results,
        "the battery admits every pair under a wider bound",
        wide_entry["pairs"],
        CHECK_PAIRS,
    )
    # the bound is two-sided: a reference still AHEAD of a test
    # observation by more than it allows is refused as well, which is the
    # half of the matching a dataset whose reference block comes second
    # is the only way to reach
    ahead = check_flat(CHECK_TEST_BITS, CHECK_PAIRS, 0) + check_flat(
        CHECK_REFERENCE_BITS, CHECK_PAIRS, CHECK_PAIRS + CHECK_SEPARATION
    )
    check(
        results,
        "the bound refuses a reference still ahead",
        matched_differences(
            ahead, CHECK_REFERENCE_BITS, CHECK_TEST_BITS, CHECK_LIMITS
        ),
        [],
    )
    check(
        results,
        "a wider bound reaches ahead",
        len(
            matched_differences(
                ahead, CHECK_REFERENCE_BITS, CHECK_TEST_BITS, wider
            )
        ),
        CHECK_PAIRS,
    )

    # the bucket cap comes from the limits, and caps the Bonferroni
    # divisor with it
    buckets = {
        CHECK_REFERENCE_BITS: [0.0] * CHECK_PAIRS,
        CHECK_TEST_BITS: [0.0] * CHECK_PAIRS,
        CHECK_OTHER_BITS: [0.0] * CHECK_PAIRS,
    }
    one_bucket = measurement_limits(
        CHECK_GAP, 1, CHECK_PREFIX_SIZES, CHECK_ALPHA
    )
    check(
        results,
        "the cap keeps the widest bucket",
        testable_bit_lengths(
            buckets, CHECK_REFERENCE_BITS, CHECK_MINIMUM, one_bucket
        ),
        [CHECK_TEST_BITS],
    )
    check(
        results,
        "the cap admits both under CHECK_LIMITS",
        testable_bit_lengths(
            buckets, CHECK_REFERENCE_BITS, CHECK_MINIMUM, CHECK_LIMITS
        ),
        [CHECK_TEST_BITS, CHECK_OTHER_BITS],
    )
    check(
        results,
        "a bucket below the floor is not testable",
        testable_bit_lengths(
            {
                CHECK_REFERENCE_BITS: [0.0] * CHECK_PAIRS,
                CHECK_TEST_BITS: [0.0] * (CHECK_MINIMUM - 1),
            },
            CHECK_REFERENCE_BITS,
            CHECK_MINIMUM,
            CHECK_LIMITS,
        ),
        [],
    )
    # and the cap reaches the battery, over the ROUND-matched path Mode 1
    # takes -- the other half of `bucket_differences()`, which no other
    # check here exercises
    timed, timings = check_round_matched()
    check(
        results,
        "the cap decides how many buckets are compared",
        check_tested(
            battery_entries(
                timed,
                CHECK_REFERENCE_BITS,
                CHECK_MINIMUM,
                CHECK_SEED,
                None,
                timings,
                one_bucket,
            )
        ),
        1,
    )
    check(
        results,
        "both buckets are compared under CHECK_LIMITS",
        check_tested(
            battery_entries(
                timed,
                CHECK_REFERENCE_BITS,
                CHECK_MINIMUM,
                CHECK_SEED,
                None,
                timings,
                CHECK_LIMITS,
            )
        ),
        2,
    )
    # the round-matched pairing itself: same rounds, so every observation
    # pairs, and the difference is the gap between the two flat durations
    check(
        results,
        "rounds pair one for one",
        len(
            round_matched_differences(
                to_micros(timed[CHECK_REFERENCE_BITS]),
                timings[CHECK_REFERENCE_BITS],
                to_micros(timed[CHECK_TEST_BITS]),
                timings[CHECK_TEST_BITS],
            )
        ),
        CHECK_PAIRS,
    )
    check(
        results,
        "a round with no counterpart drops its pair",
        len(
            round_matched_differences(
                to_micros(timed[CHECK_REFERENCE_BITS]),
                timings[CHECK_REFERENCE_BITS],
                to_micros(timed[CHECK_TEST_BITS])[1:],
                timings[CHECK_TEST_BITS][1:],
            )
        ),
        CHECK_PAIRS - 1,
    )

    # the corrected alpha comes from the limits, and is the level
    # divided by the comparisons -- the invariant the report prints
    check(
        results,
        "one comparison is uncorrected",
        corrected_alpha(1, CHECK_LIMITS),
        CHECK_ALPHA,
    )
    check(
        results,
        "eight comparisons divide the level",
        corrected_alpha(8, CHECK_LIMITS),
        CHECK_ALPHA / 8,
    )
    check(
        results,
        "no comparison leaves the level alone",
        corrected_alpha(0, CHECK_LIMITS),
        CHECK_ALPHA,
    )
    check(
        results,
        "a negative comparison count leaves it alone",
        corrected_alpha(-3, CHECK_LIMITS),
        CHECK_ALPHA,
    )
    looser = measurement_limits(CHECK_GAP, CHECK_MOST, CHECK_PREFIX_SIZES, 0.5)
    check(
        results,
        "the level itself comes from the limits",
        corrected_alpha(2, looser),
        0.25,
    )
    # and the same invariant against the LIVE level, which is what the
    # report prints beside every verdict
    check(
        results,
        "the printed correction divides the live level",
        corrected_alpha(4) == ALPHA / 4,
        True,
    )
    # the scan's own threshold comes from its limits too, so a prefix is
    # judged at the level the analysis was asked for rather than at the
    # module's
    loose_ladder = measurement_limits(
        CHECK_GAP, CHECK_MOST, CHECK_PREFIX_SIZES, 0.5
    )
    detected_at, rows = scan_prefixes(
        sample, CHECK_MINIMUM, None, loose_ladder
    )
    check(
        results,
        "the scan reads one comparison",
        check_last(rows, "comparisons"),
        1,
    )
    check(
        results,
        "the scan judges at the level it was given",
        check_last(rows, "threshold"),
        0.5,
    )

    # the settings table.  Values equal to the shipped defaults pass;
    # each broken setting is named, and naming it is the point
    check(
        results,
        "the shipped settings are accepted",
        setting_problems(1e-6, 16, 8, 10),
        [],
    )
    for label, alpha in [
        ("zero", 0.0),
        ("one", 1.0),
        ("negative", -0.5),
        ("above one", 2.0),
    ]:
        check(
            results,
            "an alpha of %s is refused" % (label,),
            check_names(setting_problems(alpha, 16, 8, 10)),
            ["ALPHA"],
        )
    check(
        results,
        "an alpha inside the interval is accepted",
        check_names(setting_problems(0.5, 16, 8, 10)),
        [],
    )
    check(
        results,
        "a bound of zero attempts is refused",
        check_names(setting_problems(1e-6, 0, 8, 10)),
        ["MAX_PAIR_GAP"],
    )
    check(
        results,
        "a bound of one attempt is accepted",
        check_names(setting_problems(1e-6, 1, 8, 10)),
        [],
    )
    check(
        results,
        "a cap of no buckets is refused",
        check_names(setting_problems(1e-6, 16, 0, 10)),
        ["MAX_TESTED_BUCKETS"],
    )
    check(
        results,
        "a cap of one bucket is accepted",
        check_names(setting_problems(1e-6, 16, 1, 10)),
        [],
    )
    check(
        results,
        "a sign test floor below one is refused",
        check_names(setting_problems(1e-6, 16, 8, 0)),
        ["SIGN_TEST_MIN_PAIRS"],
    )
    check(
        results,
        "a raised sign test floor is accepted",
        check_names(setting_problems(1e-6, 16, 8, 500)),
        [],
    )
    check(
        results,
        "every broken setting is named",
        check_names(setting_problems(0.0, 0, 0, 0)),
        [
            "ALPHA",
            "MAX_PAIR_GAP",
            "MAX_TESTED_BUCKETS",
            "SIGN_TEST_MIN_PAIRS",
        ],
    )
    # each complaint has to SAY something, since it is what a reader
    # acts on
    for name, complaint in setting_problems(0.0, 0, 0, 0):
        check(
            results,
            "the complaint about %s names a value" % (name,),
            len(complaint) > 40,
            True,
        )


def self_check_measurement_settings(results):
    """The settings a COLLECTION or an ESTIMATOR could not be made under.

    The companion to the verdict table checked above, and the answer to a
    review finding that named the gap precisely: only four constants were
    validated, so every other tunable could be edited to a value that
    produced no evidence, or invalid evidence, while the report went on
    reading as though a measurement had been made.  A trim at one half or
    beyond was reported as a trimmed mean it is not; a cap below the
    bootstrap's floor got an interval resampled from fewer pairs than the
    floor forbids, because the floor was applied before the cap; no
    resamples at all left the row reading as tested with no interval in
    it; no warm-up admitted the lazy precompute table into the first
    timed sample; and a negative prefix rung printed as a row of negative
    N over a slice that was the sample with its TAIL removed.

    Three things are pinned here.  That the shipped values pass.  That
    each broken value is NAMED, one constant at a time and all of them
    together, whether it is out of range, of the wrong type, or usable
    only until it meets another setting.  And that the tables and the
    live mapping stay in step, so a constant cannot be added to one and
    forgotten in the other -- which would reach a run as a ``KeyError``
    from inside the gate that exists to prevent exactly that class of
    surprise.
    """
    check(
        results,
        "the shipped measurement settings are accepted",
        measurement_problems(CHECK_SETTINGS),
        [],
    )
    # the tables and the live mapping have to name the same constants:
    # one missing from the mapping is a KeyError out of the gate, and one
    # missing from the broken table is a constant no check below reaches
    check(
        results,
        "the live mapping holds every setting the fixture does",
        sorted(live_settings().keys()) == sorted(CHECK_SETTINGS.keys()),
        True,
    )
    broken_names = []
    for name, _ in CHECK_BROKEN_SETTINGS:
        broken_names.append(name)
    check(
        results,
        "every setting has a broken value to be named by",
        sorted(broken_names) == sorted(CHECK_SETTINGS.keys()),
        True,
    )
    for name, value in CHECK_BROKEN_SETTINGS:
        check(
            results,
            "a %s out of range is refused" % (name,),
            check_names(measurement_problems(check_settings(name, value))),
            [name],
        )
    for name, value in CHECK_MISTYPED_SETTINGS:
        check(
            results,
            "a %s of the wrong type is refused" % (name,),
            check_names(measurement_problems(check_settings(name, value))),
            [name],
        )
    for name, value, blamed in CHECK_INCOHERENT_SETTINGS:
        check(
            results,
            "a %s that no other setting can meet is refused" % (name,),
            check_names(measurement_problems(check_settings(name, value))),
            [blamed],
        )
    # the accepting side of each boundary, so the table is not simply
    # refusing everything it is shown
    for label, name, value in [
        ("a trim of none", "TRIM_PROPORTIONS", [0.0]),
        (
            "the widest trim inside the bound",
            "TRIM_PROPORTIONS",
            [CHECK_WIDEST_TRIM],
        ),
        ("an empty prefix ladder", "PREFIX_SIZES", []),
        ("a ladder rung of one", "PREFIX_SIZES", [1]),
        ("a negative bit drop", "CONTROLLED_BIT_DROPS", [-1, 0, 300]),
        ("an empty drop list", "CONTROLLED_BIT_DROPS", []),
        ("an empty curve list", "CURVE_NAMES", []),
        ("a bootstrap floor of none", "BOOTSTRAP_MIN_SAMPLES", 0),
        ("an exact binomial cut-off of none", "EXACT_BINOM_MAX_N", 0),
        ("a negative seed", "SEED", -12345),
        ("a cap one pair above the floor", "BOOTSTRAP_MAX_PAIRS", 51),
        ("a Mode 1 floor at the bucket size", "CONTROLLED_MIN_SAMPLES", 80),
        ("a Mode 2 floor at the sample size", "MIN_BUCKET_SAMPLES", 20000),
    ]:
        check(
            results,
            "%s is accepted" % (label,),
            check_names(measurement_problems(check_settings(name, value))),
            [],
        )
    # every constant at once, in the table's own order, so the report
    # names all the edits rather than the first one it met
    every = {}
    every.update(CHECK_SETTINGS)
    for name, value in CHECK_BROKEN_SETTINGS:
        every[name] = value
    check(
        results,
        "every broken measurement setting is named",
        check_names(measurement_problems(every)),
        broken_names,
    )
    # and each complaint has to SAY something, since it is what a reader
    # acts on
    for name, complaint in measurement_problems(every):
        check(
            results,
            "the complaint about %s names a value" % (name,),
            len(complaint) > 40,
            True,
        )
    # the type guard on the verdict table: a mistyped constant there has
    # to be named as well, not raise out of its comparison
    for label, complaints in [
        ("alpha", setting_problems("1e-6", CHECK_GAP, CHECK_MOST, 10)),
        ("bound", setting_problems(CHECK_ALPHA, 1.5, CHECK_MOST, 10)),
        ("cap", setting_problems(CHECK_ALPHA, CHECK_GAP, None, 10)),
        ("floor", setting_problems(CHECK_ALPHA, CHECK_GAP, CHECK_MOST, "10")),
    ]:
        check(
            results,
            "a mistyped %s is named rather than raised" % (label,),
            len(complaints),
            1,
        )

    # the bootstrap's own two refusals.  The cap is the one the review
    # found: the floor used to be applied to the pairs AVAILABLE only, so
    # a cap below it reported an interval over fewer pairs than the floor
    # forbids
    pairs = check_boot_pairs()
    capped = bootstrap_test(
        pairs, random.Random(CHECK_SEED), [CHECK_WIDEST_TRIM], MIN_OF
    )
    check(
        results,
        "a cap below the bootstrap floor yields no interval",
        capped["intervals"],
        [],
    )
    check(
        results,
        "and the note blames the cap rather than the sample",
        capped["note"],
        "BOOTSTRAP_MAX_PAIRS caps the sample at %d of the %d pairs "
        "available, which is not more than the %d needed"
        % (MIN_OF, len(pairs), BOOTSTRAP_MIN_SAMPLES),
    )
    check(
        results,
        "the pairs it did not use are still counted as used",
        capped["used"],
        MIN_OF,
    )
    uncapped = bootstrap_test(
        pairs,
        random.Random(CHECK_SEED),
        [CHECK_WIDEST_TRIM],
        BOOTSTRAP_MIN_SAMPLES + 1,
    )
    check(
        results,
        "a cap one pair above the floor resamples",
        len(uncapped["intervals"]),
        1,
    )
    check(
        results,
        "and uses exactly what the cap left",
        uncapped["used"],
        BOOTSTRAP_MIN_SAMPLES + 1,
    )
    meeting = bootstrap_test(
        pairs, random.Random(CHECK_SEED), [CHECK_MEETING_TRIM]
    )
    check(
        results,
        "a trim whose cuts meet yields no interval",
        meeting["intervals"],
        [],
    )
    check(
        results,
        "and that note names the constant it came from too",
        meeting["note"],
        check_bad_trim_note(CHECK_MEETING_TRIM),
    )
    check(
        results,
        "the estimator itself still answers at the meeting point",
        trimmed_mean_sorted([1.0, 3.0], CHECK_MEETING_TRIM),
        2.0,
    )
    widest = bootstrap_test(
        pairs, random.Random(CHECK_SEED), [CHECK_WIDEST_TRIM]
    )
    check(
        results,
        "the widest trim inside the bound still resamples",
        len(widest["intervals"]),
        1,
    )

    # a prefix ladder rung of none or fewer is skipped rather than turned
    # into a slice: zero selects nothing and a negative rung takes the
    # sample's tail off
    sample = check_interleaved(check_balanced_offsets(CHECK_PAIRS))
    total = 2 * CHECK_PAIRS
    bad_ladder = measurement_limits(
        CHECK_GAP, CHECK_MOST, [-100, 0, CHECK_PAIRS], CHECK_ALPHA
    )
    detected_at, rows = scan_prefixes(sample, CHECK_MINIMUM, None, bad_ladder)
    check(
        results,
        "a ladder rung below one is skipped",
        check_sizes(rows),
        [CHECK_PAIRS, total],
    )
    check(
        results,
        "and the scan still reaches a verdict",
        scan_headline(detected_at, rows),
        "none",
    )


def self_check_width_classification(results):
    """A width the configuration asked for and a curve cannot supply.

    ``CONTROLLED_BIT_DROPS`` is printed in the parameters as the set of
    buckets a Mode 1 run will time, but a drop can name a width that has
    no valid nonce -- wider than the generator's order -- or one narrower
    than the probe will time at all.  Those used to be filtered out
    between the parameters and the collection, so the report named more
    buckets than it measured and said nothing about which went missing or
    why.  A reader comparing the parameters against the per-bucket table
    would have found a bucket simply absent.

    Classified against a fixed order and a fixed drop list, so the
    decision and its wording are pinned rather than sampled from whatever
    the constants happen to hold.  Two orders are used, and the second is
    the point: an order that is an exact power of two cannot supply a
    nonce of its OWN bit width, so a classifier reading supplyability off
    a bit length passes that width to the collection and the collection
    drops the bucket on the ``None`` the draw returns.  The refusal is
    checked against ``CHECK_POWER_ORDER``, and the classification of both
    orders is then checked against `nonce_of_bit_length()` itself -- for
    every width of both, and for every width of every registered curve --
    so the oracle is a draw rather than a restatement of the classifier.
    """
    check(
        results,
        "widths the curve can supply carry no reason",
        classified_widths(CHECK_ORDER, [0, 1, 4], CHECK_FLOOR),
        [
            (CHECK_ORDER_BITS, None),
            (CHECK_ORDER_BITS - 1, None),
            (CHECK_ORDER_BITS - 4, None),
        ],
    )
    check(
        results,
        "a width wider than the order is named",
        classified_widths(CHECK_ORDER, [-1], CHECK_FLOOR),
        [
            (
                CHECK_ORDER_BITS + 1,
                "wider than the %d bit order, so no nonce of that width "
                "exists" % (CHECK_ORDER_BITS,),
            )
        ],
    )
    check(
        results,
        "a width under the floor is named",
        classified_widths(
            CHECK_ORDER, [CHECK_ORDER_BITS - CHECK_FLOOR + 2], CHECK_FLOOR
        ),
        [
            (
                CHECK_FLOOR - 2,
                "below the %d bit floor this probe will time" % (CHECK_FLOOR,),
            )
        ],
    )
    check(
        results,
        "the floor itself is supplyable",
        classified_widths(
            CHECK_ORDER, [CHECK_ORDER_BITS - CHECK_FLOOR], CHECK_FLOOR
        ),
        [(CHECK_FLOOR, None)],
    )
    check(
        results,
        "the floor is the parameter, not the constant",
        check_reasons(
            classified_widths(CHECK_ORDER, [4], CHECK_ORDER_BITS - 3)
        ),
        [
            "below the %d bit floor this probe will time"
            % (CHECK_ORDER_BITS - 3,)
        ],
    )
    check(
        results,
        "a repeated width is a duplicate, not a refusal",
        check_reasons(classified_widths(CHECK_ORDER, [4, 4], CHECK_FLOOR)),
        [None, WIDTH_DUPLICATE],
    )

    # what the collection is handed, and what the report names
    check(
        results,
        "only supplyable widths are collected",
        controlled_widths(CHECK_ORDER, CHECK_DROPS, CHECK_FLOOR),
        [CHECK_ORDER_BITS, CHECK_ORDER_BITS - 1, CHECK_ORDER_BITS - 4],
    )
    check(
        results,
        "a repeated width is collected once",
        controlled_widths(CHECK_ORDER, [4, 4], CHECK_FLOOR),
        [CHECK_ORDER_BITS - 4],
    )
    check(
        results,
        "both unsupplyable widths are named",
        check_refused_bits(CHECK_ORDER, CHECK_DROPS, CHECK_FLOOR),
        [CHECK_ORDER_BITS + 1, CHECK_FLOOR - 2],
    )
    check(
        results,
        "a repeated width is not named as refused",
        refused_widths(CHECK_ORDER, [4, 4], CHECK_FLOOR),
        [],
    )
    check(
        results,
        "nothing is named when every width is supplyable",
        refused_widths(CHECK_ORDER, [0, 1, 4], CHECK_FLOOR),
        [],
    )
    # a refusal a reader cannot act on is no better than a silence
    for bits, reason in refused_widths(CHECK_ORDER, CHECK_DROPS, CHECK_FLOOR):
        check(
            results,
            "the refusal of %d bits says why" % (bits,),
            len(reason) > 20,
            True,
        )

    # and under the LIVE drops, whatever they are: every width asked for
    # is supplied, named as unsupplyable, or a repeat -- never dropped
    supplied, refused, duplicated, asked = check_width_tally(CHECK_ORDER)
    check(
        results,
        "every requested width is accounted for",
        supplied + refused + duplicated,
        asked,
    )

    # the order whose own bit width has no nonce: a power of two.  The
    # width is not wider than the order's bit length, so the message is
    # the general one rather than the "wider than the order" one, and
    # both have to exist for a reader to be told which case they are in.
    check(
        results,
        "the widest width of a power-of-two order is refused",
        classified_widths(CHECK_POWER_ORDER, [0, 1], CHECK_FLOOR),
        [
            (
                CHECK_ORDER_BITS,
                "no nonce below this %d bit order is %d bits wide, so "
                "there is none to time" % (CHECK_ORDER_BITS, CHECK_ORDER_BITS),
            ),
            (CHECK_ORDER_BITS - 1, None),
        ],
    )
    check(
        results,
        "so the collection is handed the width below it instead",
        controlled_widths(CHECK_POWER_ORDER, [0, 1], CHECK_FLOOR),
        [CHECK_ORDER_BITS - 1],
    )
    check(
        results,
        "and the width it cannot supply is named, not dropped",
        check_refused_bits(CHECK_POWER_ORDER, [0, 1], CHECK_FLOOR),
        [CHECK_ORDER_BITS],
    )
    check(
        results,
        "the same order does supply the width the classifier accepted",
        bit_length(
            nonce_of_bit_length(
                random.Random(CHECK_SEED),
                CHECK_ORDER_BITS - 1,
                CHECK_POWER_ORDER,
            )
        ),
        CHECK_ORDER_BITS - 1,
    )

    # the predicate at its boundary: one unit of order is the whole
    # difference between a width that exists and one that does not
    check(
        results,
        "the order's own width needs an order past the power of two",
        [
            width_is_supplyable(CHECK_ORDER_BITS, CHECK_POWER_ORDER),
            width_is_supplyable(CHECK_ORDER_BITS, CHECK_POWER_ORDER + 1),
        ],
        [False, True],
    )
    check(
        results,
        "one bit needs an order above one",
        [width_is_supplyable(1, 1), width_is_supplyable(1, 2)],
        [False, True],
    )
    for bits in [0, -1, -CHECK_ORDER_BITS]:
        check(
            results,
            "a width of %d bits is supplied by no order" % (bits,),
            width_is_supplyable(bits, CHECK_ORDER),
            False,
        )

    # and the classification against a DRAW rather than against itself,
    # for both synthetic orders under the fixed drops
    check(
        results,
        "every width of the odd order classifies as it draws",
        check_width_agreement(
            CHECK_ORDER,
            CHECK_DROPS,
            CHECK_FLOOR,
            random.Random(CHECK_SEED),
        ),
        ([], len(CHECK_DROPS)),
    )
    check(
        results,
        "and every width of the power-of-two order",
        check_width_agreement(
            CHECK_POWER_ORDER,
            CHECK_DROPS,
            CHECK_FLOOR,
            random.Random(CHECK_SEED),
        ),
        ([], len(CHECK_DROPS)),
    )

    # and over every registered curve, under the live drops: no synthetic
    # order can stand in for the orders a run will actually be given
    disagreed, examined, repeated, seen = check_registry_agreement(
        random.Random(CHECK_SEED)
    )
    check(results, "no registered curve disagrees either", disagreed, [])
    check(results, "over every one of them", seen, len(curves))
    check(
        results,
        "and over every width each was asked for",
        examined + repeated,
        seen * len(CONTROLLED_BIT_DROPS),
    )


def self_check_decline_reasons(results):
    """Why a bucket, a test, or a resampling produced no number.

    Every one of these printed as a bare ``-`` with its reason computed
    and then thrown away, which made a test that DECLINED read exactly
    like a test that answered with a large p-value.  Only one of those
    two says anything about a dependence on nonce bit length, so the
    distinction is the whole value of the table.

    The bucket-level reason had a second fault: a bucket held out by the
    ``MAX_TESTED_BUCKETS`` cap was reported as holding too few
    observations, which it did not, sending a reader to raise a sample
    count that was never the problem.
    """
    # the two reasons a bucket is passed over, as strings
    check(
        results,
        "a bucket short of the floor says so",
        skip_reason(CHECK_MINIMUM - 1, CHECK_MINIMUM, CHECK_MOST),
        "holds fewer than %d observations" % (CHECK_MINIMUM,),
    )
    check(
        results,
        "a bucket outside the cap says so instead",
        skip_reason(CHECK_MINIMUM, CHECK_MINIMUM, CHECK_MOST),
        "outside the %d widest eligible buckets compared" % (CHECK_MOST,),
    )
    check(
        results,
        "the two reasons are not the same reason",
        skip_reason(0, CHECK_MINIMUM, CHECK_MOST)
        == skip_reason(CHECK_MINIMUM, CHECK_MINIMUM, CHECK_MOST),
        False,
    )

    # and as the battery records them, over full buckets held out by a
    # cap of one and over a bucket that really is too small
    buckets, rounds = check_round_matched()
    one_bucket = measurement_limits(
        CHECK_GAP, 1, CHECK_PREFIX_SIZES, CHECK_ALPHA
    )
    capped = battery_entries(
        buckets,
        CHECK_REFERENCE_BITS,
        CHECK_MINIMUM,
        CHECK_SEED,
        None,
        rounds,
        one_bucket,
    )
    check(results, "the cap still lists both buckets", len(capped), 2)
    check(results, "the cap tests one of them", check_tested(capped), 1)
    check(
        results,
        "the capped bucket is named as capped",
        check_reason_of(capped, CHECK_OTHER_BITS),
        "outside the 1 widest eligible buckets compared",
    )
    short_buckets, short_rounds = check_short_buckets()
    short = battery_entries(
        short_buckets,
        CHECK_REFERENCE_BITS,
        CHECK_MINIMUM,
        CHECK_SEED,
        None,
        short_rounds,
        CHECK_LIMITS,
    )
    check(
        results,
        "a short bucket is named as short",
        check_reason_of(short, CHECK_TEST_BITS),
        "holds fewer than %d observations" % (CHECK_MINIMUM,),
    )

    # an individual test that declined inside a battery that RAN
    entries = check_entries(check_thin(1))
    rows = declined_tests(entries)
    check(
        results,
        "all three tests are named when all three decline",
        len(rows),
        len(DECLINABLE_TESTS),
    )
    check(
        results,
        "the declines are named in battery order",
        check_spoken(rows),
        ["the sign test", "the paired t test", "the Wilcoxon test"],
    )
    check(
        results,
        "each decline names its bucket",
        check_declined_widths(rows),
        [[CHECK_TEST_BITS]] * len(DECLINABLE_TESTS),
    )
    # the note printed has to be the note the test itself recorded, not
    # a second account of it written at the print site
    result = entries[0][1]
    for label, spoken in DECLINABLE_TESTS:
        check(
            results,
            "%s reports its own note" % (spoken,),
            check_note_for(rows, spoken),
            result[label]["note"],
        )
    check(
        results,
        "a test that answered is not named",
        len(declined_tests(check_entries(check_thin(2)))),
        len(DECLINABLE_TESTS) - check_finite(2),
    )
    check(
        results,
        "nothing is named when every test answers",
        len(
            declined_tests(
                check_entries(
                    check_interleaved(check_balanced_offsets(CHECK_PAIRS))
                )
            )
        ),
        len(DECLINABLE_TESTS) - check_finite(CHECK_PAIRS),
    )
    check(
        results,
        "a bucket never tested is left to the line that names it",
        declined_tests([(CHECK_TEST_BITS, declined_battery(0, "too small"))]),
        [],
    )
    shared = [
        (CHECK_TEST_BITS, result),
        (CHECK_OTHER_BITS, result),
    ]
    check(
        results,
        "buckets sharing a reason share a line",
        check_declined_widths(declined_tests(shared)),
        [[CHECK_TEST_BITS, CHECK_OTHER_BITS]] * len(DECLINABLE_TESTS),
    )

    # a resampling that declined, and the constant it blames
    differences = check_rejecting_offsets(CHECK_PAIRS)
    bad = check_interval_free(differences, [CHECK_BAD_TRIM])
    check(
        results,
        "a trim outside the allowed domain yields no interval",
        bad["bootstrap"]["intervals"],
        [],
    )
    check(
        results,
        "and the note names the constant it came from",
        bad["bootstrap"]["note"],
        check_bad_trim_note(CHECK_BAD_TRIM),
    )
    # over a sample the resampler will actually take, which is what makes
    # this a claim about the TRIM: fed a sample below the bootstrap's own
    # floor it passed for the wrong reason, the row having been refused
    # for its size before any proportion was looked at.  The success path
    # itself is `self_check_bootstrap_intervals()`.
    allowed = bootstrap_test(
        check_bootstrap_offsets(), random.Random(CHECK_SEED), CHECK_TRIMS[:1]
    )
    check(
        results,
        "a proportion is not refused as one",
        allowed["note"],
        check_running_note(),
    )
    check(
        results,
        "and the resampling it allowed produced its interval",
        len(allowed["intervals"]),
        1,
    )
    check(
        results,
        "the report surfaces the resampler's own note",
        declined_intervals([(CHECK_TEST_BITS, bad)]),
        [(bad["bootstrap"]["note"], [CHECK_TEST_BITS])],
    )
    check(
        results,
        "buckets sharing that reason share a line too",
        check_declined_widths(
            declined_intervals(
                [(CHECK_TEST_BITS, bad), (CHECK_OTHER_BITS, bad)]
            )
        ),
        [[CHECK_TEST_BITS, CHECK_OTHER_BITS]],
    )
    check(
        results,
        "two reasons make two lines",
        len(
            declined_intervals(
                [
                    (CHECK_TEST_BITS, bad),
                    (
                        CHECK_OTHER_BITS,
                        check_interval_free(
                            differences, [CHECK_BAD_TRIM - 1.0]
                        ),
                    ),
                ]
            )
        ),
        2,
    )
    check(
        results,
        "an untested bucket is not named for its missing interval",
        declined_intervals([(CHECK_TEST_BITS, declined_battery(0, "small"))]),
        [],
    )
    # and the other side of that guard: a resampling that DID produce an
    # interval must not be named as one that produced none
    filled = check_with_intervals(bad)
    check(
        results,
        "a filled bootstrap carries its interval",
        len(filled["bootstrap"]["intervals"]),
        1,
    )
    check(
        results,
        "a resampling that ran is not named",
        declined_intervals([(CHECK_TEST_BITS, filled)]),
        [],
    )
    check(
        results,
        "and naming it is still driven by the interval, not the note",
        declined_intervals([(CHECK_TEST_BITS, bad)]),
        [(filled["bootstrap"]["note"], [CHECK_TEST_BITS])],
    )


def self_check_bootstrap_intervals(results):
    """The resampling that RAN, and every trim it may not run under.

    `bootstrap_test()` was the one test of the four whose success path no
    check here reached.  Every other synthetic dataset in this section
    holds fewer rows than ``BOOTSTRAP_MIN_SAMPLES``, so every one of them
    left through the insufficient-sample branch before a single resample
    was drawn: no quantile, no trimmed mean, no endpoint, no ``used``, no
    ``excludes_zero``.  The interval column of the report -- the column a
    reader takes as evidence that a difference is real -- was therefore
    printed by code that nothing in the run had exercised, and the check
    that a valid trim is not refused passed for the wrong reason, the row
    it fed having been refused for its SIZE before any trim was read.

    So the sample here is one row past that floor, and the endpoints are
    asserted to the exact float.  Exactness is affordable because the
    samples are flat: with no spread, every resample is the same multiset
    and every trimmed mean of it is the sample's own difference, so the
    answer does not depend on what the resampler drew -- and therefore
    does not depend on which interpreter generation drew it.  The varied
    sample carries the claims a flat one cannot make: that two runs of
    one seed agree exactly, and that an interval stays inside the sample
    it came from.

    The refusals are checked over a sample that is big enough to be
    resampled, which is the only way to see that the trim was what
    stopped the row.  All three ways out of the domain are covered, and
    the reason the domain stops BELOW one half is pinned as well: at one
    half the estimator answers, and answers with a different estimator.
    """
    flat = check_flat_differences(CHECK_BOOTSTRAP_PAIRS, CHECK_FLAT_DIFFERENCE)
    ran = bootstrap_test(flat, random.Random(CHECK_SEED), CHECK_TRIMS)
    check(
        results,
        "a sample past the floor is resampled",
        check_interval_shape(ran),
        (
            len(CHECK_TRIMS),
            CHECK_TRIMS,
            CHECK_BOOTSTRAP_PAIRS,
            check_running_note(),
        ),
    )
    check(
        results,
        "and a flat sample's endpoints are its own difference",
        check_interval_bounds(ran),
        [(CHECK_FLAT_DIFFERENCE, CHECK_FLAT_DIFFERENCE, True)]
        * len(CHECK_TRIMS),
    )
    check(
        results,
        "a difference below zero excludes zero from the other side",
        check_interval_bounds(
            bootstrap_test(
                check_flat_differences(
                    CHECK_BOOTSTRAP_PAIRS, -CHECK_FLAT_DIFFERENCE
                ),
                random.Random(CHECK_SEED),
                CHECK_TRIMS,
            )
        ),
        [(-CHECK_FLAT_DIFFERENCE, -CHECK_FLAT_DIFFERENCE, True)]
        * len(CHECK_TRIMS),
    )
    # the other side of that column, and the one a reader relies on more:
    # a sample carrying no difference at all must not be reported as
    # excluding zero
    check(
        results,
        "and no difference at all excludes nothing",
        check_interval_bounds(
            bootstrap_test(
                check_flat_differences(CHECK_BOOTSTRAP_PAIRS, 0.0),
                random.Random(CHECK_SEED),
                CHECK_TRIMS,
            )
        ),
        [(0.0, 0.0, False)] * len(CHECK_TRIMS),
    )
    check(
        results,
        "one trim asked for is one interval reported",
        check_interval_shape(
            bootstrap_test(flat, random.Random(CHECK_SEED), CHECK_TRIMS[:1])
        ),
        (1, CHECK_TRIMS[:1], CHECK_BOOTSTRAP_PAIRS, check_running_note()),
    )

    # the level the interval is read at, and the level it says it is:
    # an interval labelled 95 % whose endpoints were taken at some other
    # pair of quantiles is the one error here a reader cannot see
    check(
        results,
        "the interval is read at a 95 % level",
        BOOTSTRAP_QUANTILES[1] - BOOTSTRAP_QUANTILES[0],
        0.95,
    )
    check(
        results,
        "and at symmetric tails",
        BOOTSTRAP_QUANTILES[0] + BOOTSTRAP_QUANTILES[1],
        1.0,
    )
    check(
        results,
        "and the note it carries says that level",
        check_running_note().startswith("95%"),
        True,
    )

    # a varied sample: reproducible, and bounded by the sample itself
    varied = check_bootstrap_offsets()
    check(
        results,
        "one seed resamples one sample the same way twice",
        bootstrap_test(varied, random.Random(CHECK_SEED), CHECK_TRIMS),
        bootstrap_test(varied, random.Random(CHECK_SEED), CHECK_TRIMS),
    )
    resampled = bootstrap_test(varied, random.Random(CHECK_SEED), CHECK_TRIMS)
    check(
        results,
        "a varied sample's endpoints stay inside it",
        check_intervals_within(resampled, min(varied), max(varied)),
        True,
    )
    check(
        results,
        "and a sample wholly above zero reports intervals that exclude it",
        check_interval_shape(resampled)[0],
        len(CHECK_TRIMS),
    )
    excluded = []
    for interval in resampled["intervals"]:
        excluded.append(interval["excludes_zero"])
    check(
        results,
        "every one of them",
        excluded,
        [True] * len(CHECK_TRIMS),
    )
    # and the chain from a draw to an endpoint, under draws that are
    # fixed instead of random.  With every row drawn once each resample
    # is the sample rearranged, so both endpoints are the trimmed mean
    # the estimator computes for the sample itself -- a number this
    # script does not get from its own bootstrap.
    ordered_ends = []
    for trim in CHECK_TRIMS:
        centre = trimmed_mean_sorted(sorted(varied), trim)
        ordered_ends.append((centre, centre, True))
    check(
        results,
        "drawing every row once gives the sample's own trimmed mean",
        check_interval_bounds(
            bootstrap_test(varied, CheckFixedDraws(1), CHECK_TRIMS)
        ),
        ordered_ends,
    )
    # and drawing the FIRST row every time gives that row, at every
    # trim, which the check above cannot say: a resampling that ignored
    # its resampler and took the sample as it stands would satisfy that
    # one exactly and fail this one, because the sample's trimmed mean is
    # not its smallest row.
    repeated_ends = []
    for trim in CHECK_TRIMS:
        repeated_ends.append((varied[0], varied[0], True))
    check(
        results,
        "drawing one row every time gives that row, so the draw is read",
        check_interval_bounds(
            bootstrap_test(varied, CheckFixedDraws(0), CHECK_TRIMS)
        ),
        repeated_ends,
    )
    check(
        results,
        "and that row is not the sample's trimmed mean, so they differ",
        trimmed_mean_sorted(sorted(varied), CHECK_TRIMS[0]) == varied[0],
        False,
    )

    # the boundary, from both sides: the floor is a refusal and one row
    # past it is a resampling
    check(
        results,
        "the floor itself is not resampled",
        check_interval_shape(
            bootstrap_test(
                check_flat_differences(
                    BOOTSTRAP_MIN_SAMPLES, CHECK_FLAT_DIFFERENCE
                ),
                random.Random(CHECK_SEED),
                CHECK_TRIMS,
            )
        ),
        (
            0,
            [],
            BOOTSTRAP_MIN_SAMPLES,
            "needs more than %d pairs" % (BOOTSTRAP_MIN_SAMPLES,),
        ),
    )
    # and the cap at the other end of the same range: a sample longer
    # than BOOTSTRAP_MAX_PAIRS is resampled from its prefix, so ``used``
    # has to report the rows drawn rather than the rows offered.  Drawn
    # through the fixed resampler, which keeps a two-thousand-row
    # resampling to the same fraction of a second as the rest of this
    # section.
    capped = check_flat_differences(CHECK_CAPPED_PAIRS, CHECK_FLAT_DIFFERENCE)
    capped_result = bootstrap_test(capped, CheckFixedDraws(0), CHECK_TRIMS)
    check(
        results,
        "a sample past the cap counts the rows it resampled",
        check_interval_shape(capped_result),
        (
            len(CHECK_TRIMS),
            CHECK_TRIMS,
            BOOTSTRAP_MAX_PAIRS,
            check_running_note(),
        ),
    )
    check(
        results,
        "which is fewer than the rows it was offered",
        len(capped) > BOOTSTRAP_MAX_PAIRS,
        True,
    )
    check(
        results,
        "and its endpoints are the repeated difference at every trim",
        check_interval_bounds(capped_result),
        [(CHECK_FLAT_DIFFERENCE, CHECK_FLAT_DIFFERENCE, True)]
        * len(CHECK_TRIMS),
    )

    # and a sample large enough to be resampled but holding a value that
    # is not a number is refused for THAT, not for its size
    tainted = check_flat_differences(
        CHECK_BOOTSTRAP_PAIRS, CHECK_FLAT_DIFFERENCE
    )
    tainted[0] = float("nan")
    check(
        results,
        "a value that is not a number is what stops a sample that is big",
        check_interval_shape(
            bootstrap_test(tainted, random.Random(CHECK_SEED), CHECK_TRIMS)
        ),
        (0, [], CHECK_BOOTSTRAP_PAIRS, NON_FINITE_NOTE),
    )

    # every way out of the trim domain, over a sample the size of which
    # is not the reason
    for bad_trim in CHECK_BAD_TRIMS:
        check(
            results,
            "a trim of %r is refused before any resampling" % (bad_trim,),
            check_interval_shape(
                bootstrap_test(flat, random.Random(CHECK_SEED), [bad_trim])
            ),
            (0, [], CHECK_BOOTSTRAP_PAIRS, check_bad_trim_note(bad_trim)),
        )
    check(
        results,
        "one bad trim among good ones refuses the whole row",
        check_interval_shape(
            bootstrap_test(
                flat,
                random.Random(CHECK_SEED),
                [CHECK_TRIMS[0], CHECK_BAD_TRIM],
            )
        ),
        (0, [], CHECK_BOOTSTRAP_PAIRS, check_bad_trim_note(CHECK_BAD_TRIM)),
    )

    # and a proportion outside the domain the estimator's own check
    # describes stops the interval rather than mislabelling it, whichever
    # end of the domain it falls outside: the truth table for
    # `is_trim_proportion()` itself sits with the estimator, in
    # `self_check_numeric_helpers()`
    check(
        results,
        "a trim at the half is outside what may be labelled",
        is_trim_proportion(0.5),
        False,
    )
    check(
        results,
        "and so the resampling declines rather than reporting a median",
        check_interval_shape(
            bootstrap_test(flat, random.Random(CHECK_SEED), [0.5])
        ),
        (0, [], CHECK_BOOTSTRAP_PAIRS, check_bad_trim_note(0.5)),
    )


def self_check_unmeasured_clock(results):
    """A clock resolution that was never found must not print as a number.

    ``measure_clock_resolution()`` answers ``nan`` when no two of its
    readings differed, which a coarse timer can produce however many
    readings it is given.  That reached the environment block through a
    ``%.2e`` conversion and printed as ``nan``, in a row a reader
    consults precisely to judge whether the differences further down are
    larger than the timer can resolve.  ``nan`` is not an answer to that
    question, and it is not obviously a non-answer either.

    A run now refuses a ``CLOCK_READS`` below one before it reads the
    clock, so that is no longer a way to reach the state -- but the two
    helpers stay total and are checked at zero anyway, because the
    environment block is printed BEFORE that refusal and has to render
    whatever the constant holds.  The third state below is the refusal
    itself: no reading was taken at all, which is neither a granularity
    nor a granularity that was looked for and not found.
    """
    check(
        results,
        "a granularity that was found reads as a number",
        clock_granularity(1e-07, CHECK_PAIRS),
        "1.00e-07 s (smallest non-zero gap in %d reads)" % (CHECK_PAIRS,),
    )
    check(
        results,
        "a granularity that was not found says so",
        clock_granularity(float("nan"), 0),
        "not measured (no non-zero gap in 0 reads)",
    )
    check(
        results,
        "and it says how many reads found nothing",
        clock_granularity(float("nan"), 1),
        "not measured (no non-zero gap in 1 reads)",
    )
    check(
        results,
        "the word nan never reaches the reader",
        "nan" in clock_granularity(float("nan"), 0),
        False,
    )
    check(
        results,
        "no reads finds no granularity",
        is_finite(measure_clock_resolution(0)),
        False,
    )
    check(
        results,
        "a clock never read says the settings were refused first",
        clock_granularity(1e-07, CHECK_PAIRS, False),
        "not measured (the settings below were refused first)",
    )
    check(
        results,
        "the refused state does not claim a granularity",
        "gap" in clock_granularity(float("nan"), CHECK_PAIRS, False),
        False,
    )
    check(
        results,
        "a read count that is not a number still renders",
        clock_granularity(float("nan"), "many"),
        "not measured (no non-zero gap in many reads)",
    )
    # the other two values the parameter block has to render before a
    # refusal can name them.  Both used to raise from inside the block --
    # a percent conversion and a join -- which put a traceback where the
    # name of the constant to put back belonged
    check(
        results,
        "a level that is a number is printed as one",
        shown_alpha(CHECK_ALPHA),
        "1.0e-06",
    )
    check(
        results,
        "a level that is not a number still renders",
        shown_alpha("1e-6"),
        "'1e-6'",
    )
    check(
        results,
        "a curve list of names is joined",
        shown_curves(["NIST256p", "SECP160r1"]),
        "NIST256p, SECP160r1",
    )
    check(
        results,
        "a curve list holding something else renders whole",
        shown_curves([None]),
        "[None]",
    )
    check(
        results,
        "and a curve list that is not a list renders whole",
        shown_curves("NIST256p"),
        "'NIST256p'",
    )


def run_self_check():
    """Run every check, print the tally, and answer how many failed.

    Printed as part of the report rather than kept quiet, because a
    reader who is about to read a verdict out of this script is entitled
    to see that the paths producing that verdict were exercised in this
    very run, on this interpreter.
    """
    print_section("self check")
    print(
        "  the report's own verdict paths, against synthetic inputs and\n"
        "  before any signature is timed: an empty comparison must read\n"
        "  as insufficient evidence, never as a nondetection, and never\n"
        "  as an exit status that calls the run evidence.  The statistics\n"
        "  themselves are checked here too, against values computed by\n"
        "  another route, along with the bounds each analysis is carried\n"
        "  out under and the wording the report uses for every number it\n"
        "  did NOT obtain -- a bucket it could not time, a test that\n"
        "  declined, a timer gap it never saw"
    )
    results = []
    self_check_without_evidence(results)
    self_check_with_evidence(results)
    self_check_prefix_ladder(results)
    self_check_thin_battery(results)
    self_check_verdict_states(results)
    self_check_detection_states(results)
    self_check_report_status(results)
    self_check_curve_dispatch(results)
    self_check_numeric_helpers(results)
    self_check_limits_and_settings(results)
    self_check_measurement_settings(results)
    self_check_width_classification(results)
    self_check_decline_reasons(results)
    self_check_bootstrap_intervals(results)
    self_check_unmeasured_clock(results)
    failures = []
    for label, passed, detail in results:
        if not passed:
            failures.append((label, detail))
    print("")
    if not failures:
        print("  %d checks passed" % (len(results),))
        return 0
    for label, detail in failures:
        print("  FAILED %s: %s" % (label, detail))
    print("")
    print("  %d of %d checks failed" % (len(failures), len(results)))
    return len(failures)


# --------------------------------------------------------------------
# The run.  Straight-line, no arguments, no files, no privileges --
# the same shape as speed.py, which this script sits beside.
# --------------------------------------------------------------------

CORRECTED_ALPHA_NOTE = (
    "corrected alpha = ALPHA / (buckets compared against the reference "
    "bucket),\n  Bonferroni, computed per curve and per mode and printed "
    "with each\n  result"
)

started = CLOCK()

# the settings before anything else, the clock reading included.  A
# constant that decides the verdict on its own has to be named as a
# constant, and neither the self check's datasets nor a timed collection
# can be read under one -- but the ordering here is about a second
# failure as well: a constant of the wrong TYPE would raise from inside
# the clock measurement, or from inside a collection, instead of being
# named, and a traceback out of the middle of a measurement does not
# tell a reader which line to put back.
refused_settings = configuration_problems()
if refused_settings:
    clock_resolution = float("nan")
else:
    clock_resolution = measure_clock_resolution(CLOCK_READS)

print_banner()
print_environment(clock_resolution, not refused_settings)

if refused_settings:
    print_parameters(CORRECTED_ALPHA_NOTE)
    print_settings_refusal(refused_settings)
    print_validity()
    print_csv_block()
    print_closing(CLOCK() - started)
    sys.exit(EXIT_UNAVAILABLE)

# before the measurement, not after it: a verdict path that is wrong is
# worth knowing about in the second it takes to find out rather than at
# the end of a run that spends minutes producing the verdict
if run_self_check():
    print("")
    print(
        "  the probe stops here.  A decision path of the report is "
        "wrong,\n  so nothing this run went on to print about a "
        "detection could be\n  relied on -- fix the failure above and "
        "run it again."
    )
    sys.exit(1)

print_parameters(CORRECTED_ALPHA_NOTE)
print_anchors()

if not CURVE_NAMES:
    # the loop below would otherwise fall straight through to a report
    # that measured nothing and a status saying everything was fine
    print_section("no curves requested")
    print(
        "  CURVE_NAMES is empty, so nothing was measured and there is no\n"
        "  evidence to report"
    )
    note_problem(
        "CURVE_NAMES",
        "the curve list is empty, so this run was asked for no evidence "
        "and produced none",
    )

for probe_index in range(len(CURVE_NAMES)):
    probe_name = CURVE_NAMES[probe_index]
    dispatch_state, selected_curve = curve_dispatch(probe_name)
    if dispatch_state != CURVE_RUNNABLE:
        # both modes of this curve were asked for and neither will be
        # produced, so both are registered as such before the loop moves
        # on: a skip that recorded a problem but no evidence left the
        # validity tally counting only the curves that got as far as
        # being measured
        print_section(probe_name)
        for line in wrapped_lines(
            skipped_curve_line(dispatch_state), RULE_WIDTH - 2, "  "
        ):
            print(line)
        note_skipped_curve(probe_name, dispatch_state)
        continue
    probe_curve(selected_curve, probe_index)

print_validity()
print_csv_block()
print_closing(CLOCK() - started)

# Falling off the end of a script is already an exit of EXIT_REPORTED, so that
# status is not raised: the exit call is spent only on withholding it.  Reading
# it off `exit_status()` either way keeps the status and the validity section
# above deciding from the one place.
_status = exit_status()
if _status != EXIT_REPORTED:
    sys.exit(_status)
