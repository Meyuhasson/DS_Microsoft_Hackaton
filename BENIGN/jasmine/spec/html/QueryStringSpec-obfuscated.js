var a134_0x5ada = [
    'foo',
    '425826dqAOLa',
    'toEqual',
    '71996Pruklm',
    'gets\x20the\x20query\x20string\x20including\x20the\x20given\x20key/value\x20pair',
    '137QruApK',
    'toMatch',
    'fullStringWithNewParam',
    'quux',
    '582278NuORCX',
    '#fullStringWithNewParam',
    '25505dOfGxK',
    '135977yoghdS',
    '1iuPTZZ',
    '?foo=bar',
    'baz',
    '11Dwvxel',
    'getParam',
    '10715kILwAa',
    'QueryString',
    'search',
    '531930AQHIvC',
    'quux\x20corge',
    'bar\x20baz',
    'sets\x20the\x20query\x20string\x20to\x20include\x20the\x20given\x20key/value\x20pair',
    '3ZHHeaL',
    'navigateWithNewParam',
    'returns\x20the\x20value\x20of\x20the\x20requested\x20key'
];
function a134_0x1a4c(_0x5958c8, _0x32f49c) {
    return a134_0x1a4c = function (_0x5adaf1, _0x1a4c8f) {
        _0x5adaf1 = _0x5adaf1 - 0xeb;
        var _0x30924b = a134_0x5ada[_0x5adaf1];
        return _0x30924b;
    }, a134_0x1a4c(_0x5958c8, _0x32f49c);
}
(function (_0x353dd6, _0x91e99e) {
    var _0x54c32f = a134_0x1a4c;
    while (!![]) {
        try {
            var _0x10022b = -parseInt(_0x54c32f(0x100)) * parseInt(_0x54c32f(0xf1)) + parseInt(_0x54c32f(0x104)) * -parseInt(_0x54c32f(0xff)) + -parseInt(_0x54c32f(0xf5)) + -parseInt(_0x54c32f(0xf7)) + -parseInt(_0x54c32f(0xed)) + parseInt(_0x54c32f(0x101)) * parseInt(_0x54c32f(0xfd)) + -parseInt(_0x54c32f(0xf9)) * -parseInt(_0x54c32f(0x106));
            if (_0x10022b === _0x91e99e)
                break;
            else
                _0x353dd6['push'](_0x353dd6['shift']());
        } catch (_0xa3b2f4) {
            _0x353dd6['push'](_0x353dd6['shift']());
        }
    }
}(a134_0x5ada, 0x510db), describe('QueryString', function () {
    var _0x432bee = a134_0x1a4c;
    describe('#navigateWithNewParam', function () {
        var _0x42f1d8 = a134_0x1a4c;
        it(_0x42f1d8(0xf0), function () {
            var _0x38be0a = _0x42f1d8, _0x381680 = { 'search': '' }, _0x3c26ba = new jasmineUnderTest[(_0x38be0a(0xeb))]({
                    'getWindowLocation': function () {
                        return _0x381680;
                    }
                });
            _0x3c26ba['navigateWithNewParam'](_0x38be0a(0xf4), _0x38be0a(0xef)), expect(_0x381680[_0x38be0a(0xec)])[_0x38be0a(0xfa)](/foo=bar%20baz/);
        }), it('leaves\x20existing\x20params\x20alone', function () {
            var _0x323003 = _0x42f1d8, _0x4cd3e5 = { 'search': '?foo=bar' }, _0xe45cd6 = new jasmineUnderTest[(_0x323003(0xeb))]({
                    'getWindowLocation': function () {
                        return _0x4cd3e5;
                    }
                });
            _0xe45cd6[_0x323003(0xf2)](_0x323003(0x103), 'quux'), expect(_0x4cd3e5['search'])['toMatch'](/foo=bar/), expect(_0x4cd3e5[_0x323003(0xec)])['toMatch'](/baz=quux/);
        });
    }), describe(_0x432bee(0xfe), function () {
        var _0x10caed = _0x432bee;
        it(_0x10caed(0xf8), function () {
            var _0x4c9bc1 = _0x10caed, _0x22eb77 = { 'search': _0x4c9bc1(0x102) }, _0x37bc89 = new jasmineUnderTest['QueryString']({
                    'getWindowLocation': function () {
                        return _0x22eb77;
                    }
                }), _0x1f1ba7 = _0x37bc89[_0x4c9bc1(0xfb)]('baz', _0x4c9bc1(0xfc));
            expect(_0x1f1ba7)[_0x4c9bc1(0xfa)](/foo=bar/), expect(_0x1f1ba7)[_0x4c9bc1(0xfa)](/baz=quux/);
        });
    }), describe('#getParam', function () {
        var _0xa1cdde = _0x432bee;
        it(_0xa1cdde(0xf3), function () {
            var _0x53c579 = _0xa1cdde, _0x36ccfe = { 'search': '?baz=quux%20corge' }, _0x5bbf3f = new jasmineUnderTest[(_0x53c579(0xeb))]({
                    'getWindowLocation': function () {
                        return _0x36ccfe;
                    }
                });
            expect(_0x5bbf3f[_0x53c579(0x105)](_0x53c579(0x103)))[_0x53c579(0xf6)](_0x53c579(0xee));
        }), it('returns\x20null\x20if\x20the\x20key\x20is\x20not\x20present', function () {
            var _0x3b6c37 = _0xa1cdde, _0x5d1786 = { 'search': '' }, _0x410755 = new jasmineUnderTest[(_0x3b6c37(0xeb))]({
                    'getWindowLocation': function () {
                        return _0x5d1786;
                    }
                });
            expect(_0x410755[_0x3b6c37(0x105)](_0x3b6c37(0x103)))['toBeFalsy']();
        });
    });
}));