import argparse as ap
import numpy as np

from intervaltree import IntervalTree, Interval
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler

import scipy.spatial.distance as distance

from sys import maxsize

from malloc_align import build_mallocs, build_mapping

# TODO[Process]:
# 1. Build mapping (alignment) between repr. log and trace log
# 2. Build clusters over repr log;
# 3. Identify clusters containing suspected state memory
# 4. Identify clusters containing WP hits
# 5. If WP hit in suspected state memory cluster, then consider state memory

def process_hits(repr_tlog, repr_smem, wp_tlog, wp_hits, is_zerod=False):
    # repr_smem: (base, offset, size) in allocs in repr_tlog
    # wp_hits: wp hit (base + offset) in wp_tlog

    # map wp_hit to base alloc
    wp_m = build_mallocs(wp_tlog, is_zerod=is_zerod)[0]
    wp_it = IntervalTree(Interval(m.ret, m.ret+m.arg, m) for m in wp_m)

    # build scaler and repr for r_lifetimes
    r_m, _, r_lifetimes = build_mallocs(repr_tlog, is_zerod=is_zerod)
    scaler, r_data = prepare_data(r_lifetimes)

    # build alignment
    r2wp_m = None
    kv = None
    if len(r_m) <= len(wp_m):
        r2wp_m = build_mapping(r_m, wp_m)
        kv = lambda kv: (kv[1], kv[0])
    else:
        r2wp_m = build_mapping(wp_m, r_m)
        kv = lambda kv: (kv[0], kv[1])

    r2wp_m = dict(kv(mm) for mm in r2wp_m)

    # get cluster labels for each alloc corresponding to repr_smem
    model, labels, core_samples, n_clusters = cluster_data(r_data)
    rm_it = IntervalTree(Interval(m.ret, m.ret+m.arg, (m, d, l))
                         for (m, d, l) in zip(r_m, r_data, labels))

    # map each wp onto an alloc in wp_it then get corresponding mapping in repr
    r_lbls = set()
    for (base, _, _) in repr_smem:
        ivs = rm_it.at(base).pop()
        _m, _v, label = ivs.data
        r_lbls.add(label)

    # TODO[Testing]
    # We need to know if the clustering is sensible. That is, we expect that the clusters
    # found will correspond very tightly to our learned model of state memory (i.e., the
    # set of state memory will be in a very small subset of clusters compared to the total
    # number of clusters): |C_{suspected-state-memory}| << |C_{all}|.
    print(f"smem clusters: {len(r_lbls)}; total clusters: {n_clusters}")

    # compute a partition of the WPs based on if their remapped alloc's label
    wp_nsmem = []
    wp_not_nsmem = []

    # TODO: clean this up, we don't need to predict the point if we use the
    # aligned alloc, since we can just fetch the label for the remapped label
    # keep this since we will likely use more than just the information from the
    # malloc logs to represent each point
    r_lt2fr = dict(r_lifetimes)
    for wp in wp_hits:
        wp_ivs = wp_it.at(wp)
        if len(wp_ivs) == 0:
            # TODO: handle this; it's pretty bad since it means we can't map this hit to
            # an alloc in the log from the same trace
            wp_not_nsmem.append(wp)
            continue
        m = wp_ivs.pop().data
        rm = r2wp_m.get(m, None)
        if rm is None:
            # TODO: handle this; this means that there was no mapping between the memory
            # at the WP hit and a bit of suspected state memory...
            wp_not_nsmem.append(wp)
            continue
        npt = prepare_point(rm, r_lt2fr.get(rm, None))
        _, lbl = predict_point(model, npt, scaler=scaler)

        if lbl in r_lbls:
            # OK: WP memory predicted in same cluster as assumed state memory
            wp_nsmem.append(wp)
        else:
            wp_not_nsmem.append(wp)

    return (wp_nsmem, wp_not_nsmem)


# NOTE:
# here we assume we have built a log; this isn't strictly true for the
# real impl, since we will also have offsets within allocs, and value
# data

def prepare_point(alloc, free=None):
    def free_time(free): return int(free.time) if free is not None else maxsize
    # < alloc_{time}, alloc_{time-span}, alloc_{base-address}  >
    return [int(alloc.time), free_time(free) - int(alloc.time), alloc.ret]


def prepare_data(lifetimes):
    # extract the lifetime information
    X = np.array([prepare_point(alloc, free)
                  for [alloc, free] in lifetimes.values()])
    # normalise vectors
    ss = StandardScaler().fit(X)
    return (ss, ss.transform(X))


def cluster_data(vecs):
    db = DBSCAN(min_samples=1).fit(vecs)
    labels = db.labels_

    core_samples = np.zeros_like(labels, dtype=bool)
    core_samples[db.core_sample_indices_] = True

    n_clusters = len(set(labels)) - (1 if -1 in labels else 0)

    import IPython
    IPython.embed()

    # return (db, labels, core_samples, n_clusters)


def predict_point(db, pt, scaler=None, metric=distance.euclidean):
    pt = np.array(pt).reshape(1, -1)[0]
    if scaler:
        pt = scaler.transform(pt)
    min_d = None
    predl = None
    for i, cpt in enumerate(db.components_):
        dist = metric(pt, cpt)
        if dist < db.eps:
            n_min_d = dist if min_d is None else min(dist, min_d)
            if n_min_d != min_d:
                predl = db.labels_[db.core_sample_indices_[i]]
                min_d = min_d
    return (pt, predl)


if __name__ == "__main__":
    cli = ap.ArgumentParser()
    cli.add_argument("--log", help="malloc log to cluster", required=True)
    args = cli.parse_args()
    lts = build_mallocs(args.log)[2]
    (scaler, data) = prepare_data(lts)
    cluster_data(data)
