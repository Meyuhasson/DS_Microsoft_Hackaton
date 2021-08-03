var a48_0x1745 = [
    'toEqual',
    'key',
    'hasOwnProperty',
    'when\x20using\x20a\x20regular\x20object\x20as\x20parameter',
    '269JEZyle',
    '5100erxKHq',
    '507136loFVWP',
    '3091FkNkxR',
    '469544HDtQAJ',
    'fromExisting',
    'does\x20not\x20return\x20the\x20same\x20object',
    'when\x20using\x20an\x20already\x20built\x20context\x20as\x20model',
    'returns\x20an\x20object\x20with\x20the\x20same\x20attributes',
    'cloned',
    '123XMprSg',
    'context',
    '.fromExisting',
    'returns\x20a\x20cloned\x20object',
    '497xIQcql',
    '2rMXkRo',
    'Behaves\x20just\x20like\x20an\x20plain\x20object',
    'not',
    '196NSpURR',
    'constructor',
    '2317kvUfBZ',
    'UserContext',
    '1537AvKSap',
    'value',
    'toBe',
    '157eidHwW'
];
function a48_0x59a9(_0x11e5c2, _0x1cc3a1) {
    return a48_0x59a9 = function (_0x174596, _0x59a9fc) {
        _0x174596 = _0x174596 - 0x11a;
        var _0x286cbe = a48_0x1745[_0x174596];
        return _0x286cbe;
    }, a48_0x59a9(_0x11e5c2, _0x1cc3a1);
}
(function (_0x4e8b45, _0x1ae7f3) {
    var _0x1f13f6 = a48_0x59a9;
    while (!![]) {
        try {
            var _0x66f1da = -parseInt(_0x1f13f6(0x132)) * -parseInt(_0x1f13f6(0x12a)) + -parseInt(_0x1f13f6(0x135)) * parseInt(_0x1f13f6(0x12d)) + parseInt(_0x1f13f6(0x136)) + -parseInt(_0x1f13f6(0x134)) + -parseInt(_0x1f13f6(0x128)) * -parseInt(_0x1f13f6(0x11e)) + -parseInt(_0x1f13f6(0x133)) * -parseInt(_0x1f13f6(0x123)) + -parseInt(_0x1f13f6(0x126)) * -parseInt(_0x1f13f6(0x122));
            if (_0x66f1da === _0x1ae7f3)
                break;
            else
                _0x4e8b45['push'](_0x4e8b45['shift']());
        } catch (_0x131b33) {
            _0x4e8b45['push'](_0x4e8b45['shift']());
        }
    }
}(a48_0x1745, 0x45229), describe('UserContext', function () {
    var _0x28dbea = a48_0x59a9;
    it(_0x28dbea(0x124), function () {
        var _0x59c180 = _0x28dbea, _0x1cbd1b = new jasmineUnderTest[(_0x59c180(0x129))](), _0x347112 = [];
        for (var _0x5dd8d0 in _0x1cbd1b) {
            obj[_0x59c180(0x130)](_0x5dd8d0) && _0x347112['push'](_0x5dd8d0);
        }
        expect(_0x347112)[_0x59c180(0x12e)]([]);
    }), describe(_0x28dbea(0x120), function () {
        var _0xbf5aee = _0x28dbea;
        describe(_0xbf5aee(0x11b), function () {
            var _0x147c97 = _0xbf5aee;
            beforeEach(function () {
                var _0x52e9ff = a48_0x59a9;
                this[_0x52e9ff(0x11f)] = new jasmineUnderTest['UserContext'](), this[_0x52e9ff(0x11f)][_0x52e9ff(0x12f)] = _0x52e9ff(0x12b), this[_0x52e9ff(0x11d)] = jasmineUnderTest[_0x52e9ff(0x129)][_0x52e9ff(0x137)](this[_0x52e9ff(0x11f)]);
            }), it(_0x147c97(0x121), function () {
                expect(this['cloned'])['toEqual'](this['context']);
            }), it(_0x147c97(0x11a), function () {
                var _0x1b0161 = _0x147c97;
                expect(this[_0x1b0161(0x11d)])[_0x1b0161(0x125)][_0x1b0161(0x12c)](this['context']);
            });
        }), describe(_0xbf5aee(0x131), function () {
            var _0x1f8a4c = _0xbf5aee;
            beforeEach(function () {
                var _0x76a901 = a48_0x59a9;
                this[_0x76a901(0x11f)] = {}, this[_0x76a901(0x12b)] = _0x76a901(0x12b), this[_0x76a901(0x11f)][_0x76a901(0x12f)] = this[_0x76a901(0x12b)], this[_0x76a901(0x11d)] = jasmineUnderTest[_0x76a901(0x129)][_0x76a901(0x137)](this[_0x76a901(0x11f)]);
            }), it(_0x1f8a4c(0x11c), function () {
                var _0xf447e8 = _0x1f8a4c;
                expect(this['cloned'][_0xf447e8(0x12f)])[_0xf447e8(0x12e)](this[_0xf447e8(0x12b)]);
            }), it(_0x1f8a4c(0x11a), function () {
                var _0x59fee5 = _0x1f8a4c;
                expect(this['cloned'])['not']['toBe'](this[_0x59fee5(0x11f)]);
            }), it('returns\x20an\x20UserContext', function () {
                var _0x44bf82 = _0x1f8a4c;
                expect(this[_0x44bf82(0x11d)][_0x44bf82(0x127)])[_0x44bf82(0x12c)](jasmineUnderTest[_0x44bf82(0x129)]);
            });
        });
    });
}));