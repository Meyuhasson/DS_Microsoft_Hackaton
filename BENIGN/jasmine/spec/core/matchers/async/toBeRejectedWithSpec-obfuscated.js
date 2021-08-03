var a81_0x5acf = [
    '57788epQVVC',
    'should\x20build\x20its\x20error\x20correctly\x20when\x20negated',
    'Expected\x20a\x20promise\x20to\x20be\x20rejected\x20with\x20\x27Some\x20Cool\x20Thing\x27\x20but\x20it\x20was\x20rejected\x20with\x20\x27A\x20Bad\x20Apple\x27.',
    'reject',
    '1HAbxrn',
    'resolve',
    'getEnv',
    'toBeRejectedWith',
    'then',
    '1033912ZtWOPK',
    'asyncMatchers',
    'should\x20return\x20true\x20if\x20the\x20promise\x20is\x20rejected\x20with\x20the\x20expected\x20value',
    '71387yqecVF',
    '14DQoDNq',
    'fails\x20if\x20actual\x20is\x20not\x20a\x20promise',
    '2438141HRUczg',
    'PEBCAK',
    'actual',
    'makePrettyPrinter',
    '975682OSUywQ',
    '322821fNeTLL',
    'toThrowError',
    'Expected\x20toBeRejectedWith\x20to\x20be\x20called\x20on\x20a\x20promise.',
    '#toBeRejectedWith',
    'requirePromises',
    'MatchersUtil',
    'toEqual',
    '3uYdPbk',
    'Some\x20Cool\x20Thing',
    'compare',
    'objectContaining',
    'expected',
    '475310IONYFY'
];
function a81_0x58df(_0x3fdfc4, _0x37faae) {
    return a81_0x58df = function (_0x5acf28, _0x58df97) {
        _0x5acf28 = _0x5acf28 - 0xaf;
        var _0x43c3f6 = a81_0x5acf[_0x5acf28];
        return _0x43c3f6;
    }, a81_0x58df(_0x3fdfc4, _0x37faae);
}
var a81_0x37273c = a81_0x58df;
(function (_0x31e07a, _0x3abe9e) {
    var _0x39cdcb = a81_0x58df;
    while (!![]) {
        try {
            var _0x269b61 = -parseInt(_0x39cdcb(0xb3)) + parseInt(_0x39cdcb(0xca)) + -parseInt(_0x39cdcb(0xcb)) * -parseInt(_0x39cdcb(0xb7)) + -parseInt(_0x39cdcb(0xb6)) + parseInt(_0x39cdcb(0xbd)) * -parseInt(_0x39cdcb(0xcf)) + parseInt(_0x39cdcb(0xc5)) * -parseInt(_0x39cdcb(0xbe)) + parseInt(_0x39cdcb(0xb9));
            if (_0x269b61 === _0x3abe9e)
                break;
            else
                _0x31e07a['push'](_0x31e07a['shift']());
        } catch (_0x66470a) {
            _0x31e07a['push'](_0x31e07a['shift']());
        }
    }
}(a81_0x5acf, 0xa450f), describe(a81_0x37273c(0xc1), function () {
    var _0x50a714 = a81_0x37273c;
    it(_0x50a714(0xb5), function () {
        var _0x3daa6a = _0x50a714;
        jasmine[_0x3daa6a(0xb0)]()[_0x3daa6a(0xc2)]();
        var _0x68460c = new jasmineUnderTest[(_0x3daa6a(0xc3))](), _0x4fe8e7 = jasmineUnderTest[_0x3daa6a(0xb4)][_0x3daa6a(0xb1)](_0x68460c), _0x5cb999 = Promise[_0x3daa6a(0xce)]({ 'error': _0x3daa6a(0xba) });
        return _0x4fe8e7['compare'](_0x5cb999, { 'error': 'PEBCAK' })[_0x3daa6a(0xb2)](function (_0x15e520) {
            expect(_0x15e520)['toEqual'](jasmine['objectContaining']({ 'pass': !![] }));
        });
    }), it('should\x20fail\x20if\x20the\x20promise\x20resolves', function () {
        var _0x2bfe02 = _0x50a714;
        jasmine[_0x2bfe02(0xb0)]()[_0x2bfe02(0xc2)]();
        var _0x225a73 = new jasmineUnderTest[(_0x2bfe02(0xc3))](), _0x53e36a = jasmineUnderTest[_0x2bfe02(0xb4)]['toBeRejectedWith'](_0x225a73), _0x2d11cb = Promise[_0x2bfe02(0xaf)]();
        return _0x53e36a[_0x2bfe02(0xc7)](_0x2d11cb, '')[_0x2bfe02(0xb2)](function (_0xbc340a) {
            expect(_0xbc340a)['toEqual'](jasmine['objectContaining']({ 'pass': ![] }));
        });
    }), it('should\x20fail\x20if\x20the\x20promise\x20is\x20rejected\x20with\x20a\x20different\x20value', function () {
        var _0x2c7fa2 = _0x50a714;
        jasmine[_0x2c7fa2(0xb0)]()[_0x2c7fa2(0xc2)]();
        var _0x516443 = new jasmineUnderTest['MatchersUtil']({ 'pp': jasmineUnderTest[_0x2c7fa2(0xbc)]() }), _0x2fc805 = jasmineUnderTest[_0x2c7fa2(0xb4)][_0x2c7fa2(0xb1)](_0x516443), _0x443ad9 = Promise[_0x2c7fa2(0xce)]('A\x20Bad\x20Apple');
        return _0x2fc805[_0x2c7fa2(0xc7)](_0x443ad9, _0x2c7fa2(0xc6))['then'](function (_0x128cfa) {
            var _0x7b350b = _0x2c7fa2;
            expect(_0x128cfa)[_0x7b350b(0xc4)](jasmine['objectContaining']({
                'pass': ![],
                'message': _0x7b350b(0xcd)
            }));
        });
    }), it(_0x50a714(0xcc), function () {
        var _0x32a304 = _0x50a714;
        jasmine[_0x32a304(0xb0)]()['requirePromises']();
        var _0x4bc3c2 = new jasmineUnderTest[(_0x32a304(0xc3))]({ 'pp': jasmineUnderTest[_0x32a304(0xbc)]() }), _0x3e0141 = jasmineUnderTest[_0x32a304(0xb4)][_0x32a304(0xb1)](_0x4bc3c2), _0x2298df = Promise[_0x32a304(0xce)](!![]);
        return _0x3e0141[_0x32a304(0xc7)](_0x2298df, !![])[_0x32a304(0xb2)](function (_0x194ceb) {
            var _0x331d96 = _0x32a304;
            expect(_0x194ceb)['toEqual'](jasmine[_0x331d96(0xc8)]({
                'pass': !![],
                'message': 'Expected\x20a\x20promise\x20not\x20to\x20be\x20rejected\x20with\x20true.'
            }));
        });
    }), it('should\x20support\x20custom\x20equality\x20testers', function () {
        var _0x5e996e = _0x50a714;
        jasmine['getEnv']()['requirePromises']();
        var _0x313d05 = [function () {
                    return !![];
                }], _0x50b104 = new jasmineUnderTest['MatchersUtil']({ 'customTesters': _0x313d05 }), _0x41dfe4 = jasmineUnderTest[_0x5e996e(0xb4)][_0x5e996e(0xb1)](_0x50b104), _0x1b4880 = Promise[_0x5e996e(0xce)](_0x5e996e(0xbb));
        return _0x41dfe4[_0x5e996e(0xc7)](_0x1b4880, _0x5e996e(0xc9))[_0x5e996e(0xb2)](function (_0x45d7ef) {
            var _0x3d0f61 = _0x5e996e;
            expect(_0x45d7ef)[_0x3d0f61(0xc4)](jasmine['objectContaining']({ 'pass': !![] }));
        });
    }), it(_0x50a714(0xb8), function () {
        var _0x3e55d8 = _0x50a714, _0x43bc0f = new jasmineUnderTest[(_0x3e55d8(0xc3))]({ 'pp': jasmineUnderTest[_0x3e55d8(0xbc)]() }), _0x1df01a = jasmineUnderTest[_0x3e55d8(0xb4)][_0x3e55d8(0xb1)](_0x43bc0f), _0x51a1cf = 'not\x20a\x20promise';
        function _0x21c44f() {
            var _0x32ac74 = _0x3e55d8;
            return _0x1df01a[_0x32ac74(0xc7)](_0x51a1cf);
        }
        expect(_0x21c44f)[_0x3e55d8(0xbf)](_0x3e55d8(0xc0));
    });
}));