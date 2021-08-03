var a77_0x48f2 = [
    '$.foo.bar',
    'foo123',
    'renders\x20numbers\x20as\x20array\x20access',
    '11KpLwuE',
    '$.foo123',
    '557710HMOHjx',
    'depth',
    '530737CfYpNA',
    '8663awODqk',
    'has\x20a\x20depth',
    'stringifies\x20properties\x20that\x20are\x20not\x20strings\x20or\x20numbers',
    'toString',
    '67fboZUG',
    '$.foo[0]',
    'add',
    '$[\x27[object\x20Object]\x27]',
    '1hello',
    '$.x_y',
    'renders\x20properties\x20with\x20non-identifier-safe\x20characters\x20with\x20square\x20bracket\x20notation',
    'foo',
    'renders\x20properties\x20that\x20are\x20valid\x20identifiers\x20with\x20dot\x20notation',
    '$[\x271hello\x27]',
    'renders\x20as\x20the\x20empty\x20string\x20when\x20empty',
    'ObjectPath',
    '263718lkZDrA',
    '1232292zePEgl',
    '118gyqvnL',
    'toEqual',
    'bar',
    '$.foo',
    'A$B',
    '$[\x27a\x20b\x20c\x27]',
    '4006wnKFaF',
    'can\x20be\x20created\x20based\x20on\x20another\x20path',
    '55203BWoHjg'
];
var a77_0x20ffce = a77_0x335c;
function a77_0x335c(_0xfa7019, _0x14db86) {
    return a77_0x335c = function (_0x48f28d, _0x335c60) {
        _0x48f28d = _0x48f28d - 0x6f;
        var _0x7fea40 = a77_0x48f2[_0x48f28d];
        return _0x7fea40;
    }, a77_0x335c(_0xfa7019, _0x14db86);
}
(function (_0x4f5e94, _0x2c30d3) {
    var _0x5f2960 = a77_0x335c;
    while (!![]) {
        try {
            var _0x37d804 = parseInt(_0x5f2960(0x74)) + -parseInt(_0x5f2960(0x87)) + parseInt(_0x5f2960(0x8f)) * -parseInt(_0x5f2960(0x89)) + -parseInt(_0x5f2960(0x77)) * -parseInt(_0x5f2960(0x7b)) + parseInt(_0x5f2960(0x76)) + -parseInt(_0x5f2960(0x91)) * -parseInt(_0x5f2960(0x72)) + -parseInt(_0x5f2960(0x88));
            if (_0x37d804 === _0x2c30d3)
                break;
            else
                _0x4f5e94['push'](_0x4f5e94['shift']());
        } catch (_0x19cf06) {
            _0x4f5e94['push'](_0x4f5e94['shift']());
        }
    }
}(a77_0x48f2, 0x4b0b7), describe(a77_0x20ffce(0x86), function () {
    var _0x61c14f = a77_0x20ffce, _0x21fa08 = jasmineUnderTest[_0x61c14f(0x86)];
    it('represents\x20the\x20path\x20to\x20a\x20node\x20in\x20an\x20object\x20tree', function () {
        var _0x3d23d6 = _0x61c14f;
        expect(new _0x21fa08([
            _0x3d23d6(0x82),
            _0x3d23d6(0x8b)
        ])[_0x3d23d6(0x7a)]())[_0x3d23d6(0x8a)](_0x3d23d6(0x6f));
    }), it(_0x61c14f(0x78), function () {
        var _0x3b0fb1 = _0x61c14f;
        expect(new _0x21fa08()['depth']())[_0x3b0fb1(0x8a)](0x0), expect(new _0x21fa08([_0x3b0fb1(0x82)])[_0x3b0fb1(0x75)]())[_0x3b0fb1(0x8a)](0x1);
    }), it(_0x61c14f(0x71), function () {
        var _0x2c14f4 = _0x61c14f;
        expect(new _0x21fa08([
            _0x2c14f4(0x82),
            0x0
        ])[_0x2c14f4(0x7a)]())[_0x2c14f4(0x8a)](_0x2c14f4(0x7c));
    }), it(_0x61c14f(0x83), function () {
        var _0x27c49d = _0x61c14f;
        expect(new _0x21fa08([_0x27c49d(0x70)])[_0x27c49d(0x7a)]())[_0x27c49d(0x8a)](_0x27c49d(0x73)), expect(new _0x21fa08(['x_y'])['toString']())[_0x27c49d(0x8a)](_0x27c49d(0x80)), expect(new _0x21fa08([_0x27c49d(0x8d)])[_0x27c49d(0x7a)]())['toEqual']('$.A$B');
    }), it(_0x61c14f(0x81), function () {
        var _0x3a6e51 = _0x61c14f;
        expect(new _0x21fa08(['a\x20b\x20c'])[_0x3a6e51(0x7a)]())[_0x3a6e51(0x8a)](_0x3a6e51(0x8e)), expect(new _0x21fa08([_0x3a6e51(0x7f)])[_0x3a6e51(0x7a)]())[_0x3a6e51(0x8a)](_0x3a6e51(0x84));
    }), it(_0x61c14f(0x85), function () {
        var _0xd710bb = _0x61c14f;
        expect(new _0x21fa08()[_0xd710bb(0x7a)]())[_0xd710bb(0x8a)]('');
    }), it(_0x61c14f(0x79), function () {
        var _0x1c1e01 = _0x61c14f;
        expect(new _0x21fa08([{}])[_0x1c1e01(0x7a)]())[_0x1c1e01(0x8a)](_0x1c1e01(0x7e));
    }), it(_0x61c14f(0x90), function () {
        var _0x20d7c1 = _0x61c14f, _0x16809f = new _0x21fa08(), _0x3bddb1 = _0x16809f[_0x20d7c1(0x7d)](_0x20d7c1(0x82));
        expect(_0x3bddb1[_0x20d7c1(0x7a)]())[_0x20d7c1(0x8a)](_0x20d7c1(0x8c)), expect(_0x16809f[_0x20d7c1(0x7a)]())[_0x20d7c1(0x8a)]('');
    });
}));