var a131_0x28fc = [
    '468201YUmXop',
    'should\x20match\x20when\x20no\x20string\x20is\x20provided',
    '*bar',
    '2QiIWLg',
    'should\x20only\x20match\x20the\x20provided\x20string',
    '727lTomhr',
    'foo',
    '7Tapkye',
    'jasmineUnderTest.HtmlSpecFilter',
    'matches',
    '1313779ldWtnl',
    '1475264lONdcK',
    '206861YPNzjJ',
    '109kimWEq',
    '317486AaZpgC',
    '1690STdMCr',
    '8271OCtHeH',
    'toBe'
];
var a131_0x299d1a = a131_0x4113;
function a131_0x4113(_0x1ae3d3, _0x3af5c0) {
    return a131_0x4113 = function (_0x28fccd, _0x41132d) {
        _0x28fccd = _0x28fccd - 0x189;
        var _0x2677e4 = a131_0x28fc[_0x28fccd];
        return _0x2677e4;
    }, a131_0x4113(_0x1ae3d3, _0x3af5c0);
}
(function (_0x2d1b92, _0x372144) {
    var _0x70154 = a131_0x4113;
    while (!![]) {
        try {
            var _0x5186de = parseInt(_0x70154(0x190)) + parseInt(_0x70154(0x18c)) * -parseInt(_0x70154(0x191)) + -parseInt(_0x70154(0x19a)) * parseInt(_0x70154(0x193)) + parseInt(_0x70154(0x197)) + -parseInt(_0x70154(0x18a)) * parseInt(_0x70154(0x194)) + parseInt(_0x70154(0x18f)) + -parseInt(_0x70154(0x192)) * -parseInt(_0x70154(0x195));
            if (_0x5186de === _0x372144)
                break;
            else
                _0x2d1b92['push'](_0x2d1b92['shift']());
        } catch (_0x4dc977) {
            _0x2d1b92['push'](_0x2d1b92['shift']());
        }
    }
}(a131_0x28fc, 0xced32), describe(a131_0x299d1a(0x18d), function () {
    var _0x7dcc0f = a131_0x299d1a;
    it(_0x7dcc0f(0x198), function () {
        var _0x1224cc = _0x7dcc0f, _0x59f56b = new jasmineUnderTest['HtmlSpecFilter']();
        expect(_0x59f56b[_0x1224cc(0x18e)](_0x1224cc(0x18b)))[_0x1224cc(0x196)](!![]), expect(_0x59f56b[_0x1224cc(0x18e)](_0x1224cc(0x199)))[_0x1224cc(0x196)](!![]);
    }), it(_0x7dcc0f(0x189), function () {
        var _0x289d05 = _0x7dcc0f, _0x1a01e5 = new jasmineUnderTest['HtmlSpecFilter']({
                'filterString': function () {
                    return 'foo';
                }
            });
        expect(_0x1a01e5[_0x289d05(0x18e)](_0x289d05(0x18b)))[_0x289d05(0x196)](!![]), expect(_0x1a01e5[_0x289d05(0x18e)]('bar'))[_0x289d05(0x196)](![]);
    });
}));