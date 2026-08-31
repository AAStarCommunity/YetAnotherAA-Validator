// The sentinel classifier, extracted so it can be tested against SYNTHETIC state.
//
// WHY IT LIVES HERE. The exemption below decides whether an unsatisfiable `requiredQuorum()` is a
// page or a shrug, and it got that wrong once already: `beforeWindow` was excluded, so the first
// block of every epoch paged CRITICAL on a healthy stack. Nothing guarded it, because the only tests
// available were live reads -- and the failing state (bn == start, e-1 unusable) cannot be produced
// on demand from a live chain, nor replayed, since it needs archive state.
//
// So the safety boundary of the widened exemption -- `usablePrev` -- had no test at all. That
// conjunct is the whole reason widening is safe: at bn == start, if e-1 is ALSO unusable then
// nothing serves and it must still be CRITICAL. A pure function can be handed exactly that.
//
// Raised by pr-daemon on #274: "you verified the retired stack is still CRITICAL, but that cell does
// not pass through bn == start, so it proves nothing about this boundary."

/**
 * Is an unsatisfiable sentinel benign right now?
 *
 * Benign means: the CURRENT epoch is not usable only because it has not been pinned yet, while
 * epoch e-1 still serves every payload. Anything else -- e-1 unusable, the pin window missed, the
 * CC-97 floor unmet, a pre-D2 contract -- is a real page.
 */
export function isBenignPendingPin({ isD2, usableE, usablePrev, floorOk, pinnedE, pastWindow }) {
  return Boolean(isD2 && !usableE && usablePrev && floorOk && !pinnedE && !pastWindow);
}
