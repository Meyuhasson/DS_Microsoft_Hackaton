var a114_0x1bef = [
    'oh\x20no',
    'nope',
    'Expected\x20function\x20to\x20throw\x20an\x20exception\x20matching\x20a\x20predicate,\x20but\x20it\x20threw\x20undefined.',
    '193plDZTE',
    '553277oLNQZE',
    'toThrowError',
    'passes\x20if\x20the\x20argument\x20is\x20a\x20function\x20that\x20returns\x20true\x20when\x20called\x20with\x20the\x20error',
    '2lCAeto',
    'Expected\x20function\x20not\x20to\x20throw\x20an\x20exception\x20matching\x20a\x20predicate.',
    '85451eyzbXI',
    'throws\x20an\x20error\x20when\x20the\x20expected\x20is\x20not\x20a\x20function',
    'Expected\x20function\x20to\x20throw\x20an\x20exception.',
    'fails\x20if\x20the\x20argument\x20is\x20a\x20function\x20that\x20returns\x20false\x20when\x20called\x20with\x20the\x20error',
    'fails\x20if\x20actual\x20does\x20not\x20throw\x20at\x20all',
    'compare',
    'throws\x20an\x20error\x20when\x20the\x20actual\x20is\x20not\x20a\x20function',
    '240119UaRcje',
    '4yXyIVM',
    'toThrowMatching',
    'message',
    '1yrSnbb',
    'Expected\x20function\x20to\x20throw\x20an\x20exception\x20matching\x20a\x20predicate,\x20but\x20it\x20threw\x20TypeError\x20with\x20message\x20\x27nope\x27.',
    '3659IcKMLn',
    '1312838YQqihN',
    '670529Glqptq',
    '1KxxELN',
    '1VlUtHc',
    'makePrettyPrinter',
    'matchers',
    'toEqual',
    '28537ekBbeI',
    'toBe',
    'pass',
    'foo',
    '17kCfjYs'
];
function a114_0x2efa(_0x67c23b, _0x6a0046) {
    return a114_0x2efa = function (_0x1bef96, _0x2efac4) {
        _0x1bef96 = _0x1bef96 - 0xaa;
        var _0x2b7abe = a114_0x1bef[_0x1bef96];
        return _0x2b7abe;
    }, a114_0x2efa(_0x67c23b, _0x6a0046);
}
var a114_0x5969d9 = a114_0x2efa;
(function (_0x1f8c0a, _0x1a57ab) {
    var _0x107798 = a114_0x2efa;
    while (!![]) {
        try {
            var _0x25b1d5 = parseInt(_0x107798(0xb0)) * parseInt(_0x107798(0xac)) + parseInt(_0x107798(0xcb)) * -parseInt(_0x107798(0xb5)) + -parseInt(_0x107798(0xc2)) * parseInt(_0x107798(0xc1)) + parseInt(_0x107798(0xc9)) * -parseInt(_0x107798(0xca)) + parseInt(_0x107798(0xb8)) * parseInt(_0x107798(0xba)) + -parseInt(_0x107798(0xc7)) * -parseInt(_0x107798(0xb4)) + parseInt(_0x107798(0xc5)) * parseInt(_0x107798(0xc8));
            if (_0x25b1d5 === _0x1a57ab)
                break;
            else
                _0x1f8c0a['push'](_0x1f8c0a['shift']());
        } catch (_0x3365bf) {
            _0x1f8c0a['push'](_0x1f8c0a['shift']());
        }
    }
}(a114_0x1bef, 0x77d16), describe(a114_0x5969d9(0xc3), function () {
    var _0xc5e162 = a114_0x5969d9;
    it(_0xc5e162(0xc0), function () {
        var _0x360db3 = _0xc5e162, _0x4393a5 = jasmineUnderTest[_0x360db3(0xaa)]['toThrowMatching']();
        expect(function () {
            _0x4393a5['compare']({}, function () {
                return !![];
            });
        })[_0x360db3(0xb6)](/Actual is not a Function/);
    }), it(_0xc5e162(0xbb), function () {
        var _0x12b0c6 = _0xc5e162, _0x3b2834 = jasmineUnderTest[_0x12b0c6(0xaa)][_0x12b0c6(0xc3)](), _0x221cbd = function () {
                var _0x4278ac = _0x12b0c6;
                throw new Error(_0x4278ac(0xaf));
            };
        expect(function () {
            var _0x1449bb = _0x12b0c6;
            _0x3b2834[_0x1449bb(0xbf)](_0x221cbd, 0x1);
        })[_0x12b0c6(0xb6)](/Predicate is not a Function/);
    }), it(_0xc5e162(0xbe), function () {
        var _0x3ee365 = _0xc5e162, _0x28b0d2 = jasmineUnderTest['matchers'][_0x3ee365(0xc3)](), _0x4b33c4 = function () {
                return !![];
            }, _0x32f77e;
        _0x32f77e = _0x28b0d2['compare'](_0x4b33c4, function () {
            return !![];
        }), expect(_0x32f77e[_0x3ee365(0xae)])[_0x3ee365(0xad)](![]), expect(_0x32f77e[_0x3ee365(0xc4)])[_0x3ee365(0xab)](_0x3ee365(0xbc));
    }), it('fails\x20with\x20the\x20correct\x20message\x20if\x20thrown\x20is\x20a\x20falsy\x20value', function () {
        var _0x46c557 = _0xc5e162, _0x1a93fe = jasmineUnderTest['matchers']['toThrowMatching']({ 'pp': jasmineUnderTest[_0x46c557(0xcc)]() }), _0x26faca = function () {
                throw undefined;
            }, _0x55bf01;
        _0x55bf01 = _0x1a93fe['compare'](_0x26faca, function () {
            return ![];
        }), expect(_0x55bf01[_0x46c557(0xae)])[_0x46c557(0xad)](![]), expect(_0x55bf01[_0x46c557(0xc4)]())[_0x46c557(0xab)](_0x46c557(0xb3));
    }), it(_0xc5e162(0xb7), function () {
        var _0xaebf62 = _0xc5e162, _0xd56fda = jasmineUnderTest[_0xaebf62(0xaa)][_0xaebf62(0xc3)](), _0x3613b2 = function (_0x58f290) {
                var _0x130a96 = _0xaebf62;
                return _0x58f290['message'] === _0x130a96(0xb2);
            }, _0x2ca04b = function () {
                var _0x342ee3 = _0xaebf62;
                throw new TypeError(_0x342ee3(0xb2));
            }, _0x45c00d;
        _0x45c00d = _0xd56fda[_0xaebf62(0xbf)](_0x2ca04b, _0x3613b2), expect(_0x45c00d['pass'])['toBe'](!![]), expect(_0x45c00d[_0xaebf62(0xc4)])[_0xaebf62(0xab)](_0xaebf62(0xb9));
    }), it(_0xc5e162(0xbd), function () {
        var _0x596ece = _0xc5e162, _0x24d966 = jasmineUnderTest[_0x596ece(0xaa)]['toThrowMatching']({ 'pp': jasmineUnderTest['makePrettyPrinter']() }), _0x1fb903 = function (_0x1990e5) {
                var _0x116628 = _0x596ece;
                return _0x1990e5[_0x116628(0xc4)] === _0x116628(0xb1);
            }, _0x11f47c = function () {
                var _0x5e132a = _0x596ece;
                throw new TypeError(_0x5e132a(0xb2));
            }, _0x4840eb;
        _0x4840eb = _0x24d966[_0x596ece(0xbf)](_0x11f47c, _0x1fb903), expect(_0x4840eb[_0x596ece(0xae)])['toBe'](![]), expect(_0x4840eb[_0x596ece(0xc4)]())[_0x596ece(0xab)](_0x596ece(0xc6));
    });
}));