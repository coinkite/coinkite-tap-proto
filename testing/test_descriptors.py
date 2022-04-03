from cktap.descriptors import descsum_create, descsum_check

def test_simple_descsum_check():
    d1 = "addr(tb1qdu05evh9kw0w482lfl2ktxm6ylp060kmqpe5js)"
    d2 = "wpkh(cU7CGBhwnMdLDbqBaXm3xE22KFyaA5s3YDBis88LyuPLnmfpDFFU)"

    for d in [d1, d2]:
        d_w_sum = descsum_create(d)
        assert descsum_check(d_w_sum)

