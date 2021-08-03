var a110_0x1fad = [
    'compare',
    'foo',
    '5TAXllV',
    '279260QMcWvu',
    'createElementWithClassName',
    '48343pcTfQN',
    'foo\x20bar\x20baz',
    '163660hAGAGI',
    'toBe',
    'fails\x20for\x20a\x20DOM\x20element\x20that\x20lacks\x20the\x20expected\x20class',
    '13nufODS',
    'document',
    'Object({\x20classList:\x20\x27\x27\x20})\x20is\x20not\x20a\x20DOM\x20element',
    'foo\x20bar',
    '1739918cxVmBc',
    'toThrowError',
    'makePrettyPrinter',
    'createTextNode',
    'domHelpers',
    '34521tOUjtw',
    '1fuIZeh',
    '514581llxzGw',
    'undefined\x20is\x20not\x20a\x20DOM\x20element',
    'getEnv',
    'bar',
    'throws\x20an\x20exception\x20when\x20actual\x20is\x20not\x20a\x20DOM\x20element',
    '\x27x\x27\x20is\x20not\x20a\x20DOM\x20element',
    'matchers',
    'toHaveClass',
    'pass',
    '370813jMylcG'
];
function a110_0x30f0(_0x3536b9, _0x3b6d5a) {
    return a110_0x30f0 = function (_0x1fadac, _0x30f0a7) {
        _0x1fadac = _0x1fadac - 0x156;
        var _0x42f037 = a110_0x1fad[_0x1fadac];
        return _0x42f037;
    }, a110_0x30f0(_0x3536b9, _0x3b6d5a);
}
(function (_0x2d6a5b, _0x3ab022) {
    var _0x3af782 = a110_0x30f0;
    while (!![]) {
        try {
            var _0x26ed57 = -parseInt(_0x3af782(0x159)) * parseInt(_0x3af782(0x162)) + -parseInt(_0x3af782(0x163)) * parseInt(_0x3af782(0x16d)) + parseInt(_0x3af782(0x171)) + parseInt(_0x3af782(0x170)) * -parseInt(_0x3af782(0x173)) + -parseInt(_0x3af782(0x156)) + -parseInt(_0x3af782(0x164)) + parseInt(_0x3af782(0x15d));
            if (_0x26ed57 === _0x3ab022)
                break;
            else
                _0x2d6a5b['push'](_0x2d6a5b['shift']());
        } catch (_0x461b95) {
            _0x2d6a5b['push'](_0x2d6a5b['shift']());
        }
    }
}(a110_0x1fad, 0x44454), describe('toHaveClass', function () {
    var _0x1403a1 = a110_0x30f0;
    beforeEach(function () {
        var _0x5bc497 = a110_0x30f0;
        this['domHelpers'] = jasmine[_0x5bc497(0x166)]()[_0x5bc497(0x161)]();
    }), it(_0x1403a1(0x158), function () {
        var _0x404595 = _0x1403a1, _0x4dbd26 = jasmineUnderTest[_0x404595(0x16a)][_0x404595(0x16b)](), _0x2250a5 = _0x4dbd26['compare'](this[_0x404595(0x161)][_0x404595(0x172)](''), _0x404595(0x16f));
        expect(_0x2250a5[_0x404595(0x16c)])['toBe'](![]);
    }), it('passes\x20for\x20a\x20DOM\x20element\x20that\x20has\x20the\x20expected\x20class', function () {
        var _0x465c5b = _0x1403a1, _0x295858 = jasmineUnderTest[_0x465c5b(0x16a)][_0x465c5b(0x16b)](), _0x44bf7d = this['domHelpers'][_0x465c5b(0x172)](_0x465c5b(0x174));
        expect(_0x295858[_0x465c5b(0x16e)](_0x44bf7d, _0x465c5b(0x16f))[_0x465c5b(0x16c)])[_0x465c5b(0x157)](!![]), expect(_0x295858['compare'](_0x44bf7d, 'bar')[_0x465c5b(0x16c)])[_0x465c5b(0x157)](!![]), expect(_0x295858[_0x465c5b(0x16e)](_0x44bf7d, _0x465c5b(0x167))[_0x465c5b(0x16c)])['toBe'](!![]);
    }), it('fails\x20for\x20a\x20DOM\x20element\x20that\x20only\x20has\x20other\x20classes', function () {
        var _0xc40998 = _0x1403a1, _0x4973ce = jasmineUnderTest['matchers'][_0xc40998(0x16b)](), _0x38e961 = this['domHelpers'][_0xc40998(0x172)](_0xc40998(0x15c));
        expect(_0x4973ce[_0xc40998(0x16e)](_0x38e961, 'fo')[_0xc40998(0x16c)])[_0xc40998(0x157)](![]);
    }), it(_0x1403a1(0x168), function () {
        var _0x50fafa = _0x1403a1, _0x46b32 = jasmineUnderTest[_0x50fafa(0x16a)][_0x50fafa(0x16b)]({ 'pp': jasmineUnderTest[_0x50fafa(0x15f)]() });
        expect(function () {
            var _0x8a4d98 = _0x50fafa;
            _0x46b32[_0x8a4d98(0x16e)]('x', _0x8a4d98(0x16f));
        })[_0x50fafa(0x15e)](_0x50fafa(0x169)), expect(function () {
            var _0x54e5fd = _0x50fafa;
            _0x46b32[_0x54e5fd(0x16e)](undefined, _0x54e5fd(0x16f));
        })[_0x50fafa(0x15e)](_0x50fafa(0x165));
        var _0x14a009 = this[_0x50fafa(0x161)][_0x50fafa(0x15a)][_0x50fafa(0x160)]('');
        expect(function () {
            var _0x3dd7ab = _0x50fafa;
            _0x46b32[_0x3dd7ab(0x16e)](_0x14a009, _0x3dd7ab(0x16f));
        })[_0x50fafa(0x15e)]('HTMLNode\x20is\x20not\x20a\x20DOM\x20element'), expect(function () {
            var _0x39e7d9 = _0x50fafa;
            _0x46b32[_0x39e7d9(0x16e)]({ 'classList': '' }, 'foo');
        })[_0x50fafa(0x15e)](_0x50fafa(0x15b));
    });
}));