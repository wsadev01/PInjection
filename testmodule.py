def test_function():
    USER32.MessageBoxW(
        0,
        'Test Function!',
        'Function test!',
        MB_OK
        )