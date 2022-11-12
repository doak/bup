
from binascii import hexlify, unhexlify
from time import localtime, strftime

from bup import options, git
from bup.compat import argv_bytes
from bup.helpers import exo, log, qprogress
from bup.io import path_msg

# Just does what rev-parse does

optspec = """
bup check-refs [OPTION...] [REF_PATTERN...]
--
unrelated  specify when the refs are likely unrelated to save RAM
commit-hash ...
connectivity-only ...
v,verbose   increase verbosity (can be used more than once)
"""

#FIXME: It should not print a chunked file as "tree".
def report_item(commit_prefix, item, verbosity):
    assert verbosity > 0, "don't call report_item if not verbose"

    if verbosity < 3 and item.type == b'blob':
        return
    # Don't print mangled paths unless the verbosity is over 3.
    if verbosity < 4 and item.chunk_path and item.chunk_path != [b'']:
        return

    typestr = {
        b'commit':  "cmmt",
        b'tree':    "tree",
        b'blob':    "blob",
        None:       "????",
    }
    log(f"{hexlify(item.oid).decode()} ({typestr[item.type]}): {commit_prefix}")

    if (item.type == b'commit'):
        log('\n')
        return

    if verbosity >=4 and item.chunk_path:
        path = []
        path += item.path
        path += item.chunk_path
        if item.type == b'tree':
            path.append(b'')  # adds trailing slash
        log(b': ' + b'/'.join(path) + b'\n')
        return

    # Top commit, for example has none.
    demangled = git.demangle_name(item.path[-1], item.mode)[0] if item.path \
                else None
    if demangled:
        ps = b'/'.join(item.path[:-1] + [demangled])
    else:
        ps = b'/'.join(item.path)
    path = path_msg(ps)
    if item.type == b'tree':
        path += "/"

    if verbosity == 1:
        qprogress(path + '\r')
    elif (verbosity == 2 and item.type == b'tree') or (verbosity > 2):
        log(f": {path}\n")

def report_missing_oidx(item, commit_context, out):
    report_item(f"non-existing object, referenced by commit {commit_context}", item, 4)


# FIXME: does gc walk all tags?

# For now the output uses spaces to delimit REF, COMMIT_INFO_IF_COMMIT, and PATH

# YYYY-MM-DD/opt-hash/path -- commit
# HASH/path/ -- tree
# HASH/path -- blob

def fsck_ref(ref, oid, visited, *, commit_hash=False, connectivity_only=False,
             verbose=0, out):
    git.check_repo_or_die()
    cat_pipe = git.cp()
    stop_at = lambda x: unhexlify(x) in visited

    ref_prefix = path_msg(ref) + ' '
    commit_prefix = ref_prefix + ' '
    for item in git.walk_object(cat_pipe.get, hexlify(oid), stop_at=stop_at,
                                include_data=(not connectivity_only),
                                for_missing=lambda item, commit_context: report_missing_oidx(item, commit_context, out)):
        if verbose:
            if item.type == b'commit':
                commit = git.parse_commit(item.data)
                commit_utc = commit.author_sec + commit.author_offset
                commit_prefix = ref_prefix + strftime('%Y-%m-%d-%H%M%S', localtime(commit_utc))
                if commit_hash:
                    commit_prefix += commit.tree.decode('ascii')
                report_item(commit_prefix, item, verbose)
            else:
                report_item(commit_prefix, item, verbose)
        if item.type in (b'tree', b'commit'):
            visited.add(item.oid)

def via_cmdline(args, *, out):
    o = options.Options(optspec)
    opt, flags, extra = o.parse_bytes(args)
    opt.verbose = opt.verbose or 0

    refs = [argv_bytes(x) for x in extra]
    if refs:
        # --revs-only ?
        ref_oidxs = exo((b'git', b'rev-parse', b'--revs-only',
                         b'--end-of-options', *refs))[0].splitlines()
        ref_info = list(zip(refs, (unhexlify(x) for x in ref_oidxs)))
    else:
        ref_info = git.list_refs()

    visited = set()
    for ref, oid in ref_info:
        if opt.unrelated:
            visited = set()
        fsck_ref(ref, oid, visited,
                 commit_hash=opt.commit_hash,
                 connectivity_only=opt.connectivity_only,
                 verbose=opt.verbose,
                 out=out)
    return 0
