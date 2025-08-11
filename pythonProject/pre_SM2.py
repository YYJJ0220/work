A = 0
B = 7
G_X = 55066263022277343669578718895168534326250603453777594175500187360389116729240
G_Y = 32670510020758816978083085130507043184471273380659243275938904335757337482424
G = (G_X, G_Y)
P = 115792089237316195423570985008687907853269984665640564039457584007908834671663
N = 115792089237316195423570985008687907852837564279074904382605163141518161494337
h = 1


def inv(a, n):
#求逆
    def ext_gcd(a, b, arr):
        if b == 0:
            arr[0] = 1
            arr[1] = 0
            return a
        g = ext_gcd(b, a % b, arr)
        t = arr[0]
        arr[0] = arr[1]
        arr[1] = t - int(a / b) * arr[1]
        return g

    arr = [0, 1, ]
    gcd = ext_gcd(a, n, arr)
    if gcd == 1:
        return (arr[0] % n + n) % n
    else:
        return -1


def EC_add(p, q):
#椭圆曲线
    # 0 means inf
    if p == 0 and q == 0:
        return 0  # 0 + 0 = 0
    elif p == 0:
        return q  # 0 + q = q
    elif q == 0:
        return p  # p + 0 = p
    else:
        if p[0] == q[0]:
            if (p[1] + q[1]) % P == 0:
                return 0
            elif p[1] == q[1]:
                return EC_double(p)
        elif p[0] &gt; q[0]:
            tmp = p
            p = q
            q = tmp
        r = []
        slope = (q[1] - p[1]) * inv(q[0] - p[0], P) % P
        r.append((slope ** 2 - p[0] - q[0]) % P)
        r.append((slope * (p[0] - r[0]) - p[1]) % P)
        return (r[0], r[1])


def EC_inv(p):
    r = [p[0]]
    r.append(P - p[1])
    return r
def EC_sub(p, q):
    q_inv = EC_inv(q)
    return EC_add(p, q_inv)
def EC_double(p):
    r = []
    slope = (3 * p[0] ** 2 + A) * inv(2 * p[1], P) % P
    r.append((slope ** 2 - 2 * p[0]) % P)
    r.append((slope * (p[0] - r[0]) - p[1]) % P)
    return (r[0], r[1])


def EC_multi(s, p):
    """椭圆曲线多倍点运算
    1.param s: 倍数
    2.param p: 点
    3.return: 运算结果
    """
    n = p
    r = 0
    s_bin = bin(s)[2:]
    s_len = len(s_bin)

    for i in reversed(range(s_len)):
        if s_bin[i] == '1':
            r = EC_add(r, n)
        n = EC_double(n)

    return r


def get_bit_num(x):
    if isinstance(x, int):  # when int
        num = 0
        tmp = x &gt;&gt; 64
        while tmp:
            num += 64
            tmp &gt;&gt;= 64
        tmp = x &gt;&gt; num &gt;&gt; 8
        while tmp:
            num += 8
            tmp &gt;&gt;= 8
        x &gt;&gt;= num
        while x:
            num += 1
            x &gt;&gt;= 1
        return num
    elif isinstance(x, str):
        return len(x.encode()) &lt;&lt; 3
    elif isinstance(x, bytes):
        return len(x) &lt;&lt; 3
    return 0