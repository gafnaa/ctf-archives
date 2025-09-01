from sage.all import *
import itertools


# from original implementation https://github.com/anemoi-hash/anemoi-hash/blob/main/anemoi.sage


def is_mds(m):
    # Uses the Laplace expansion of the determinant to calculate the (m+1)x(m+1) minors in terms of the mxm minors.
    # Taken from https://github.com/mir-protocol/hash-constants/blob/master/mds_search.sage.

    # 1-minors are just the elements themselves
    if any(any(r == 0 for r in row) for row in m):
        return False

    N = m.nrows()
    assert m.is_square() and N >= 2

    det_cache = m

    # Calculate all the nxn minors of m:
    for n in range(2, N + 1):
        new_det_cache = dict()
        for rows in itertools.combinations(range(N), n):
            for cols in itertools.combinations(range(N), n):
                i, *rs = rows

                # Laplace expansion along row i
                det = 0
                for j in range(n):
                    # pick out c = column j; the remaining columns are in cs
                    c = cols[j]
                    cs = cols[:j] + cols[j + 1:]

                    # Look up the determinant from the previous iteration
                    # and multiply by -1 if j is odd
                    cofactor = det_cache[(*rs, *cs)]
                    if j % 2 == 1:
                        cofactor = -cofactor

                    # update the determinant with the j-th term
                    det += m[i, c] * cofactor

                if det == 0:
                    return False
                new_det_cache[(*rows, *cols)] = det
        det_cache = new_det_cache
    return True


def M_2(x_input, b):
    x = x_input[:]
    x[0] += b * x[1]
    x[1] += b * x[0]
    return x


def M_3(x_input, b):
    x = x_input[:]
    t = x[0] + b * x[2]
    x[2] += x[1]
    x[2] += b * x[0]
    x[0] = t + x[2]
    x[1] += t
    return x


def M_4(x_input, b):
    x = x_input[:]
    x[0] += x[1]
    x[2] += x[3]
    x[3] += b * x[0]
    x[1] = b * (x[1] + x[2])
    x[0] += x[1]
    x[2] += b * x[3]
    x[1] += x[2]
    x[3] += x[0]
    return x


def lfsr(x_input, b):
    x = x_input[:]
    l = len(x)
    for r in range(0, l):
        t = sum(b ** (2 ** i) * x[i] for i in range(0, l))
        x = x[1:] + [t]
    return x


def circulant_mds_matrix(field, l, coeff_upper_limit=None):
    if coeff_upper_limit == None:
        coeff_upper_limit = l + 1
    assert (coeff_upper_limit > l)
    for v in itertools.combinations_with_replacement(range(1, coeff_upper_limit), l):
        mat = matrix.circulant(list(v)).change_ring(field)
        if is_mds(mat):
            return (mat)
    # In some cases, the method won't return any valid matrix,
    # hence the need to increase the limit further.
    return circulant_mds_matrix(field, l, coeff_upper_limit + 1)


def get_mds(field, l):
    if l == 1:
        return identity_matrix(field, 1)
    if l <= 4:  # low addition case
        a = field.multiplicative_generator()
        b = field.one()
        t = 0
        while True:
            # we construct the matrix
            mat = []
            b = b * a
            t += 1
            for i in range(0, l):
                x_i = [field.one() * (j == i) for j in range(0, l)]
                if l == 2:
                    mat.append(M_2(x_i, b))
                elif l == 3:
                    mat.append(M_3(x_i, b))
                elif l == 4:
                    mat.append(M_4(x_i, b))
            mat = Matrix(field, l, l, mat).transpose()
            if is_mds(mat):
                return mat
    else:  # circulant matrix case
        return circulant_mds_matrix(field, l)
