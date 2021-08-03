var a112_0x305e = [
    'throws\x20an\x20Error\x20when\x20the\x20expected\x20is\x20not\x20a\x20String\x20or\x20RegExp',
    '88456VcfwNT',
    'compare',
    'foosball',
    '4296646seiyiJ',
    'foo',
    'passes\x20when\x20the\x20actual\x20matches\x20the\x20expected\x20string\x20as\x20a\x20pattern',
    '124876fwNGZq',
    'fails\x20when\x20RegExps\x20are\x20not\x20equivalent',
    'matchers',
    '1VRnnGE',
    'pass',
    'toBe',
    'toThrowError',
    'baz',
    '4uFnZAo',
    '717387MkOpDm',
    'toMatch',
    '1384873VmzmcU',
    '1087317gccZcK',
    'bar',
    '252557dhxibF'
];
function a112_0x438d(_0x12c59a, _0x16b5a2) {
    return a112_0x438d = function (_0x305e5e, _0x438d54) {
        _0x305e5e = _0x305e5e - 0x64;
        var _0x5beedb = a112_0x305e[_0x305e5e];
        return _0x5beedb;
    }, a112_0x438d(_0x12c59a, _0x16b5a2);
}
(function (_0x3ba02b, _0xe84c91) {
    var _0x528724 = a112_0x438d;
    while (!![]) {
        try {
            var _0x27c01d = -parseInt(_0x528724(0x75)) * parseInt(_0x528724(0x6d)) + -parseInt(_0x528724(0x68)) * -parseInt(_0x528724(0x73)) + -parseInt(_0x528724(0x65)) + -parseInt(_0x528724(0x70)) + -parseInt(_0x528724(0x6e)) + -parseInt(_0x528724(0x71)) + parseInt(_0x528724(0x78));
            if (_0x27c01d === _0xe84c91)
                break;
            else
                _0x3ba02b['push'](_0x3ba02b['shift']());
        } catch (_0x186396) {
            _0x3ba02b['push'](_0x3ba02b['shift']());
        }
    }
}(a112_0x305e, 0xd711e), describe('toMatch', function () {
    var _0x1cbb0a = a112_0x438d;
    it('passes\x20when\x20RegExps\x20are\x20equivalent', function () {
        var _0x248851 = a112_0x438d, _0x2587e0 = jasmineUnderTest[_0x248851(0x67)][_0x248851(0x6f)](), _0x1a9884;
        _0x1a9884 = _0x2587e0[_0x248851(0x76)](/foo/, /foo/), expect(_0x1a9884['pass'])[_0x248851(0x6a)](!![]);
    }), it(_0x1cbb0a(0x66), function () {
        var _0x542b90 = _0x1cbb0a, _0x5bd956 = jasmineUnderTest['matchers']['toMatch'](), _0x57f320;
        _0x57f320 = _0x5bd956[_0x542b90(0x76)](/bar/, /foo/), expect(_0x57f320['pass'])[_0x542b90(0x6a)](![]);
    }), it(_0x1cbb0a(0x64), function () {
        var _0x415269 = _0x1cbb0a, _0xa6b40a = jasmineUnderTest[_0x415269(0x67)][_0x415269(0x6f)](), _0x36effa;
        _0x36effa = _0xa6b40a['compare'](_0x415269(0x77), 'foo'), expect(_0x36effa[_0x415269(0x69)])[_0x415269(0x6a)](!![]);
    }), it('fails\x20when\x20the\x20actual\x20matches\x20the\x20expected\x20string\x20as\x20a\x20pattern', function () {
        var _0x9672c5 = _0x1cbb0a, _0x53455d = jasmineUnderTest[_0x9672c5(0x67)][_0x9672c5(0x6f)](), _0x3605ac;
        _0x3605ac = _0x53455d[_0x9672c5(0x76)](_0x9672c5(0x72), _0x9672c5(0x79)), expect(_0x3605ac['pass'])[_0x9672c5(0x6a)](![]);
    }), it(_0x1cbb0a(0x74), function () {
        var _0x118cac = _0x1cbb0a, _0x2da6a1 = jasmineUnderTest[_0x118cac(0x67)]['toMatch']();
        expect(function () {
            var _0x1aa3be = _0x118cac;
            _0x2da6a1[_0x1aa3be(0x76)](_0x1aa3be(0x79), { 'bar': _0x1aa3be(0x6c) });
        })[_0x118cac(0x6b)](/Expected is not a String or a RegExp/);
    });
}));