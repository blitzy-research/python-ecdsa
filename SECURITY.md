# Security Policy

## Supported Versions

Only the latest released version is supported.
Alpha and beta releases are always unsupported with security fixes.

The project uses semantic versioning, as such, minor version changes are API compatible.

| Version  | Supported          |
| -------- | ------------------ |
| 0.19.x   | :white_check_mark: |
| < 0.19   | :x:                |

## Support Scope

This library was not designed with security in mind. If you are processing data that needs
to be protected we suggest you use a quality wrapper around OpenSSL.
[`pyca/cryptography`](https://cryptography.io/) is one example of such a wrapper.
The primary use-case of this library is as a portable library for interoperability testing
and as a teaching tool.

**This library does not protect against side-channel attacks in general, and makes no
constant-time guarantee for any operation.** One reported timing side channel has been
narrowed, and only that one: the number of elliptic curve point operations that signing,
key generation, EdDSA signing and an ECDH exchange schedule is now fixed by the public
parameters of the curve rather than by the secret they are performed with -- by its order
where the point carries one and by its field where the point carries no order, as a remote
public point decoded from an encoding does. One rare exception survives on the Edwards curves,
where at most two multipliers per order cost a single doubling beyond that schedule. It is
described below, together with what the change does and does not cover; read that before
relying on any of it.

Do not allow attackers to measure how long it takes you to generate a key pair or sign a message.
Do not allow attackers to run code on the same physical machine when key pair generation or
signing is taking place (this includes virtual machines).
Do not allow attackers to measure how much power your computer uses while generating the key pair
or signing a message. Do not allow attackers to measure RF interference coming from your computer
while generating a key pair or signing a message. Note: just loading the private key will cause
key pair generation. Other operations or attack vectors may also be vulnerable to attacks. 
Against the power analysis, RF and same-machine attacks in that list this library implements no
countermeasure whatsoever. Some local physical or microarchitectural attacks may recover key
material from very few observations; this library provides no protection against them.

Side-channel resistance is not a design goal of this library, no operation of it is claimed to be
constant time, and complete resistance to attacks of this class remains out of scope for a
pure-Python implementation. Reports of such leaks are nonetheless considered, and where a specific
leak is both measurable and reducible without native code it may be reduced. One such reduction
has been made: see [Nonce bit-length hardening](#nonce-bit-length-hardening-cve-2024-23342) below,
which is described in terms of what it removes and what it leaves behind rather than as a
guarantee. It reduces one measured signal; it does not change any sentence above.

Please also note that any Pure-python cryptographic library will remain vulnerable to side-channel
attacks whatever is done at the level described below. This is because Python does not provide
side-channel secure primitives
(with the exception of [`hmac.compare_digest()`](https://docs.python.org/3/library/hmac.html#hmac.compare_digest)),
and gives a program no control over the width or the cost of the integer operations it performs,
making side-channel secure programming impossible. That is the reason a residual signal remains,
and the reason nothing stronger than a measured reduction is claimed here.

This library depends upon a strong source of random numbers. Do not use it on a system
where `os.urandom()` does not provide cryptographically secure random numbers.

### Nonce bit-length hardening (CVE-2024-23342)

[CVE-2024-23342](https://nvd.nist.gov/vuln/detail/CVE-2024-23342), published as
[GHSA-wj6h-64fc-37mp](https://github.com/tlsfuzzer/python-ecdsa/security/advisories/GHSA-wj6h-64fc-37mp)
and as PYSEC-2026-1325, reports a [Minerva](https://minerva.crocs.fi.muni.cz/) class timing attack
against this library. The time `ecdsa.SigningKey.sign_digest()` took followed the bit length of the
per-signature nonce, so an attacker able to ask for enough timed signatures under one key learned a
few bits of every nonce and reassembled those partial leaks into the long-term private key by
lattice reduction. Key generation and ECDH key agreement multiply by the private key over the same
code and were affected the same way, and EdDSA signing multiplies by a per-signature value of its
own. Signature verification was never affected by this attack, since its multipliers are derived
from values that are public as soon as the signature is, and its combined multiplication has
deliberately been left alone -- `PointJacobi.mul_add()` is unchanged, statement for statement, as
are all seven of the addition and doubling formulas underneath it. That leaves one consequence worth
stating rather than glossing over: `mul_add()` has always short-circuited to two separate
multiplications when both of its points carry a precomputation table, which is the case once
`VerifyingKey.precompute()` has been called, so verification with a precomputed key does now run
through the hardened ladder. It reaches the same point from the same public multipliers, and
measurably faster; verification without a precomputed key is untouched and unchanged in speed.

**What has changed.** Where a point knows an order the recoding can use -- which is every curve
this library registers -- the multiplier is reduced to the one odd representative of it that lies
between that order and three times it, and recoded into a fixed length sequence of digits none of
which is zero, so how many point additions and point doublings a multiplication schedules are
derived from that (public) order and from nothing else. Scheduled work is the whole cost of every
multiplier but the at most two per order that a twisted Edwards ladder answers with one doubling
more, set out with the other bounds below. That the representative is never smaller than the
order matters on its own: a Python integer costs what its width costs, so a normalisation that left
a short nonce short would have kept the bit length of the nonce in the cost of recoding it and of
every shift the ladder performs, even with the number of operations already fixed. The width of that
representative is not itself a constant and is not claimed to be one: it runs from the bit length of
the order to the bit length of three times the order less two, so up to two bits above the order,
and the narrowest of those widths occurs only where the residue of the multiplier is even. On every
curve this library registers that whole band falls inside one CPython integer size -- a 256-bit
order gives representatives of 256 to 258 bits, every one of which CPython holds in nine of its
30-bit internal digits -- so the width that remains does not change how many limbs the arithmetic
works over. That is a measured property of the orders this library registers, not a promise about an
order a caller brings of their own.

Two things carried the old signal. The former ladder skipped an addition on a zero digit, so its
operation count tracked the Hamming weight of the NAF recoding of the multiplier; and the nonce
bit-length padding added in 0.14 was cancelled further down by a reduction modulo twice the order,
so it did nothing for the very case that needed it -- the "nonce unpadding" failure the side
channel analysis of Mozilla's NSS (arXiv:2008.06004) describes. There is no longer a padding for a
reduction to undo. Separately, the modular inversion of the nonce is performed on a blinded value
and unblinded afterwards, so the iterations of the extended Euclid loop that two of the four
inversion implementations run no longer follow the nonce either. That blinding factor is drawn
afresh for every signature, so what is inverted is unrelated to the nonce; the entropy that costs
is disclosed under **Compatibility** below.

The resulting count is fixed per code path, and is not one number for the whole library:

* once a generator has built its precomputation table, which the first multiplication pays for,
  signing and key generation perform 65 point additions and no doublings at all on NIST256p,
  whatever the nonce, where the old ladder ranged over dozens of distinct counts -- about twenty
  additions for a nonce a quarter of the full width against about ninety for a full-width one;
* the count collapses to a single value on every other curve too: 65 on SECP256k1 and
  BRAINPOOLP256r1, 41 on SECP160r1, 64 on Ed25519, 131 on NIST521p;
* building that table, and multiplying a point that has no table at all as ECDH does, each settle
  on a count of their own, fixed by the curve in the same way;
* known-order affine multiplication delegates to the hardened path;
* EdDSA signing on the Edwards curves uses the same recoding, with one exception, disclosed here
  rather than removed. The digit of the lowest position is added last, to an accumulator that by
  then holds the canonical multiplier less that digit times the point, and the two operands of that
  addition coincide exactly where the canonical value is congruent to twice that digit modulo the
  order. At most two residues of any order qualify: seven of the registered curves have two of them
  (NIST521p, and BRAINPOOLP160, BRAINPOOLP256 and BRAINPOOLP512 in both their r1 and t1 forms),
  eighteen have exactly one, and SECP160r1 has none at all, so a nonce reaches one with probability
  of the order of two divided by the order itself -- about 2\*\*-255 on a 256-bit curve. Where it
  does happen a short Weierstrass ladder answers that addition from inside the addition formula
  and dispatches no further operation, while a twisted Edwards ladder dispatches a doubling and so
  performs one operation more than every other multiplier does. Removing it would mean giving every
  multiplication an unconditional extra doubling, which is a worse trade than recording it;
* a point whose order the recoding cannot use keeps the older multiplication, whose cost follows
  its multiplier. Such an order is even, or below 17, and both are consequences of the mechanism
  rather than choices. An even order has no odd representative for the multiplier to be reduced to,
  since adding an even number to a residue cannot change its parity; and an order below 17 cannot
  be recoded at all, because one of the eight odd multiples of the point that a digit position
  indexes -- one, three and so on up to fifteen -- would then be a multiple of the order and so the
  point at infinity, which an affine table entry cannot hold. Every curve this library registers
  declares an odd order of at least 110 bits, so neither of those two reaches a registered curve --
  a recoding narrow enough to be two digits wide covers orders 17 to 63, and only a group a caller
  assembles themselves can be that small;
* a point that reports no order at all is covered too, against its curve rather than against an
  order, and this is the ECDH case the advisory names. A public point decoded from an encoding
  carries no order: `VerifyingKey.from_string()` builds it from coordinates alone and nothing
  attaches the order of the curve to it, so an exchange against a peer key that arrived over the
  wire multiplies the long-term private key by a point that knows nothing about its group. Hasse's
  theorem bounds the number of points of a curve over a field of p elements to within 2\*sqrt(p) of
  p + 1, and the order of any point divides that number, so no order of the curve reaches
  2\*\*(bit_length(p) + 1). That bound supplies the width the missing order cannot. The multiplier
  is made odd by setting its lowest bit -- one bitwise operation, no branch -- recoded into the digit
  count the bound gives, and this point is then subtracted from the product of that odd form; both
  answers are derived for every multiplier and its parity picks one out by index, so neither parity
  costs an operation the other does not. Such an exchange therefore costs 73 point additions and 257
  doublings on NIST256p whatever the private key is, where releases up to 0.19.1 spent exactly the
  bit length of that key in doublings -- measured 256, 192, 128 and 64 for private keys of those
  widths. That is one addition above the 72 and 257 the same exchange costs against a public key
  this process derived from a `SigningKey`, and a digit more on a curve whose group is narrower than
  its field: 37 additions and 113 doublings on SECP112r2, of a 110-bit group over a 112-bit field.
  Which of the two counts an exchange spends says which shape of point the caller handed in, and
  neither of them says anything about the key;
* what stays on the older ladder is therefore narrow, and a test enumerates it: an order that is
  even or below 17; a multiplier of a point with no order that is negative, or wider than every
  group of its curve, neither of which a private key or a nonce can be, both being drawn from
  [1, order); a point with no order that is flagged as a curve generator, which cannot build the
  table that flag promises and which every release since 0.14 refuses to multiply at all; and an
  affine point without a usable order, which no secret reaches, `ecdsa.ecdsa.Public_key` refusing a
  generator that declares no order. A point accepted by `VerifyingKey.from_string()` with
  `validate_point=False` that belongs to a subgroup smaller than the one the base point generates
  is multiplied at the fixed cost of its curve like any other point of it -- a table entry that
  lands on the point at infinity is added as the point at infinity, which is what that multiple of
  the point is, so the product is right and the count does not move. It is right in one case where
  the older ladder was not: on a subgroup of seven points that ladder answered one multiplier in
  twenty-one with the point at infinity in place of the correct multiple, which the fixed recoding
  gets right. None of these cases is rejected instead: rejecting would withdraw a documented
  opt-out, and it would not make the multiplication any cheaper to hide.

**Compatibility.** Signatures are unchanged: the same key and the same nonce produce the same
signature as before, byte for byte, what the multiplication adds to a multiplier being a multiple
of the order of the point, and RFC 6979 deterministic signatures remain reproducible byte for
byte. Public call signatures, key encodings and signature encodings are unchanged, and no public
return type changed. The container a point writes when it is pickled is unchanged: it is the plain
instance dictionary, precomputation table and all, exactly what every release up to 0.19.1 wrote,
so no reader has to learn a new format. Its contents are not unchanged -- the precomputation table
inside it now holds, for each digit position, the odd multiples of the point a whole window can
select, where earlier releases cached successive doublings -- so compatibility runs one way only. A
point unpickled with a precomputation table an earlier release wrote is accepted, that table being
recognised as one of another layout, discarded and lazily rebuilt. The opposite direction is not
guarded and cannot be: a state written by this code
and read by a release older than the countermeasure hands that release a table of the new layout
to index as the successive doublings it expects, and it has no check that would notice, so it
would answer with a wrong point rather than raise. That residual is accepted. It is inherent to
changing the layout of a cache that a serialised point has always carried, and the alternative --
leaving the table out of the state -- would change the format for every reader instead of for none.

Three things did change that a caller can observe or depend on, and this is the whole list: the
layout of the precomputation table inside a pickled point, described just above; the refusal of a
multiplier standing for no integer, described next; and the entropy read and the `RuntimeError`
that can come with it, described after that.

A multiplier is read for the integer it stands for before anything else a multiplication does with
it, and one that stands for no integer is refused with a `TypeError` naming its type: `multiplier
must be an integer, not str`, and so on. The reading is `operator.index()` first, which takes `int`,
`bool` and the `mpz` of both gmpy releases losslessly and reads only their type, never their value;
then, for a value of some other type, a conversion that is accepted only if the integer it yields
still compares equal to the value it came from. A `float`, `Fraction` or `Decimal` with no
fractional part therefore stands for exactly one integer and is still answered with that multiple of
the point, exactly as releases up to 0.19.1 answered it -- 2.0, `Fraction(4, 2)` and `Decimal("2")`
all give twice the point. What reaches the ladder is the integer, though, and the value itself never
reaches the arithmetic. That is what closes off release 1.17 of the older of the two gmpy bindings,
which answers a float taken modulo a number as wide as a curve order by attempting an allocation of
exabytes and aborting the interpreter: every release up to 0.19.1 performed exactly that reduction,
on the projective paths and on the affine one alike, so with that binding installed
`ecdsa.NIST256p.generator * 2.5` was enough to take the process down.

What is refused is what stands for no one integer, and those releases answered several of them,
differently on each shape of point. The Jacobi and Edwards paths took any float in silence and
answered with a multiple no caller had asked for: 2.5, 3.5 and 3.9 all gave three times the point,
and 0.5 gave one times it. The affine path answered 0.5 with one times the point as well, but
raised a `TypeError` about the `&` operator for every float from two upwards -- including 2.0 and
3.0, which the other two paths answered correctly, so the three did not agree even on the values
they took. A `complex` of one was answered with the point on the two projective paths, the shortcut
for a multiplier of one comparing for equality. A `None` or an empty sequence was read as a zero and
answered with the point at infinity there, and raised from the reduction on the affine one. A `str`,
a `list` or a `bytes` raised a `TypeError` carrying a message about string formatting or about the
`%` operator that said nothing of multiplication. Refusing every one of those is the one answer that
cannot be a wrong point, and it is deliberate rather than incidental: the shortcut that answers a
multiplier of one had to move behind the reading step, or a nonce of one would never reach a ladder
at all, and a value with a fraction to lose cannot be read as an integer without guessing what its
caller meant.

Whether anything is lost is asked of the value in its own type, before any integer is built from it,
which is why a `Decimal` naming an integer wider than the precision of the `decimal` context the
caller set is refused rather than converted: converting `Decimal("1e1000000000")` outright would ask
for the allocation of a billion digits before being refused anyway. That boundary is the caller's own
context and moves with it, exactly as it moved for releases up to 0.19.1, which reduced such a value
modulo twice the order of the point and were answered by the same context with `InvalidOperation`.
Those releases allowed one digit more than this, their reduction needing only the remainder to fit
where this needs the integral part to, so a `Decimal` of exactly that one width -- 29 integral digits
at the default precision of 28 -- is the only value they answered correctly that is refused here.
A `Fraction` carries its own integer and meets no such limit.

So of the values releases up to 0.19.1 accepted, every one that stood for an integer is answered with
the same multiple as before, save that one `Decimal` width, and is newly answered on the affine path
where it used to raise; the ones that stood for none -- a fraction, a `complex`, a value that is
merely false -- are refused where two of the three paths answered them with a point; and a `str`, a
`list` or a `bytes` was refused before and is refused now, only by a message naming the multiplier
instead of whichever operation reached it first. A multiplier this library itself forms is never any
of these:
`util.randrange()`, `rfc6979.generate_k()`, the nonce padding and the scalars recovered by key
decoding all produce integers, so nothing on a signing, key generation or ECDH path reaches the
second half of the reading step, and no secret is ever looked at rather than merely typed.

The third of those changes is not visible in the output at all. Signing draws one factor to blind
the modular inversion per signature and reads `os.urandom()` at least once to obtain it -- the
rejection sampling of `util.randrange()` reads it again for every draw it discards, and a factor
that is not invertible modulo a composite generator order is drawn again as well -- so it reads
from the system entropy source where earlier releases did not: when the caller passed the nonce in,
and when the nonce is the deterministic one of RFC 6979. That draw is separate from the `entropy=`
argument, which continues to feed nonce generation only, and it does not reach the signature, the
blinding cancelling exactly. Should the entropy source refuse, signing raises `RuntimeError` -- the
exception `ecdsa.ecdsa.Private_key.sign()` has always documented, rather than the `OSError` of the
source -- instead of falling back to an unblinded inversion, so exhausting the entropy source
cannot be used to switch the countermeasure off.

**What this does not do.**

* It does not make an operation take the same amount of time. Python integers are variable width
  and cost more to work with as they grow, and the field arithmetic deliberately skips the
  reduction modulo the field prime where that is faster, so individual operations still differ in
  duration even though their number no longer does. A residual timing signal therefore remains.
  How much of the original signal is left is a question of measurement, not of guarantee.
* It does nothing at all about power analysis, electromagnetic emanation, cache timing or any other
  microarchitectural side channel. None of those is addressed anywhere in this library.
* It is not a constant-time implementation and is not claimed to be one. A constant-time guarantee
  is not attainable in pure Python at all, for the reason given above.
* It is local hardening only, and creates no upstream patched-version marker. No release is
  recorded anywhere as fixing CVE-2024-23342 -- the advisory lists every version as affected and
  none as patched -- so a vulnerability scanner will keep reporting CVE-2024-23342 and
  PYSEC-2026-1325 against this library whether or not the countermeasure is present.

For a sense of scale: the same researchers found the same class of defect in GnuTLS, and after it
was fixed there, in compiled C, a residual leak of roughly 34 ns was still measurable over about
43 million observations. If you need more than a measured reduction of one leak, use a quality
wrapper around a hardened native implementation such as
[`pyca/cryptography`](https://cryptography.io/), as suggested above, rather than this library.

**Measuring it.** The evidence lives in the repository rather than in this document.
`src/ecdsa/test_side_channel.py` pins the point operation counts above to exact numbers and runs as
part of the normal test suite. `minerva_probe.py`, in the repository root, measures the wall clock
signal that remains: it times signatures, groups them by the bit length of the nonce that produced
each one, and applies the statistical battery the external `tlsfuzzer` harness applies to the same
question. It tests the configured `PREFIX_SIZES` and reports the earliest rejecting configured
prefix, or that no rejection occurred at the tested prefixes through the largest of them. That is
an observation about the prefixes tested and nothing more: no threshold is inferred, and nothing is
claimed about the sample counts between two of them. It is opt-in and is deliberately not part of
the default test run or of CI, a statistical
timing measurement being unusable as a pass/fail gate:

```
tox -e leak
```

It exits 0 when it produced a usable report, 1 when its own self-check failed, and 2 when it
could not produce a report it is willing to stand behind. It certifies nothing: a smaller measured
signal is a smaller measured signal and no more than that. Run it before and after any change to
`ellipticcurve.py` or to the nonce handling in `ecdsa.py`.

## Reporting a Vulnerability

If you find a security vulnerability in this library, you can report it using the "Report a vulnerability" button on the Security tab in github UI.
Alternatively, you can contact the project maintainer at hkario at redhat dot com.
