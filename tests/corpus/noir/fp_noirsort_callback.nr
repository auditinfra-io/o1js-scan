// @recall-rule NONE
// @recall-expect-absent NOIR_UNCONSTRAINED_WITNESS
//
// Real code: noir_sort src/lib.nr:87-104. `sorted` comes from an unconstrained
// quicksort, then every adjacent pair is constrained by the caller-supplied
// `sortfn_assert` callback. The callback's name has no word boundary before
// "assert", so a `\bassert` pattern cannot see it at all.
pub fn sort_advanced<T, let N: u32>(
    input: [T; N],
    sortfn: unconstrained fn(T, T) -> bool,
    sortfn_assert: fn(T, T) -> (),
) -> SortResult<T, N>
where
    T: std::cmp::Eq,
{
    // Safety: validated using check_shuffle. See its documentation for more info.
    let sorted = unsafe { quicksort_explicit(input, sortfn) };

    let sort_indices = get_shuffle_indices(input, sorted);

    for i in 0..N - 1 {
        sortfn_assert(sorted[i], sorted[i + 1]);
    }
    SortResult { sorted, sort_indices }
}
