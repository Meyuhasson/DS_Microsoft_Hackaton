var a133_0x34ea = [
    '3066559ivdocc',
    '20hbFYBg',
    'className',
    'createTextNode',
    '<div\x20things=\x22foo\x22>...</div>',
    'createElement',
    'HTMLNode',
    'toEqual',
    'should\x20stringify\x20non-element\x20HTML\x20nodes\x20properly',
    '34328zvcFob',
    '268301dHaZzJ',
    'toMatch',
    'should\x20print\x20Firefox\x27s\x20wrapped\x20native\x20objects\x20correctly',
    '3uojueV',
    'makePrettyPrinter',
    'innerHTML',
    'firefoxVersion',
    '75209lcbmcE',
    'things',
    '232TUGCus',
    'Object({\x20foo:\x20HTMLNode\x20})',
    '716285aQudcT',
    '805360WKrFWD',
    '853SPoNRr',
    '10tHhJpU',
    '<div\x20class=\x22foo\x22>...</div>',
    'div',
    '<p>Irrelevant</p>',
    'should\x20stringify\x20non-empty\x20HTML\x20elements\x20as\x20tags\x20with\x20placeholders',
    'foo',
    '<div\x20class=\x22foo\x22>'
];
function a133_0x5c83(_0x3cce57, _0x49b380) {
    return a133_0x5c83 = function (_0x34eacc, _0x5c83ba) {
        _0x34eacc = _0x34eacc - 0x1dd;
        var _0x30b150 = a133_0x34ea[_0x34eacc];
        return _0x30b150;
    }, a133_0x5c83(_0x3cce57, _0x49b380);
}
(function (_0x3ab8b3, _0x1fa8b2) {
    var _0x451b7d = a133_0x5c83;
    while (!![]) {
        try {
            var _0xe0796 = parseInt(_0x451b7d(0x1e6)) * -parseInt(_0x451b7d(0x1e3)) + parseInt(_0x451b7d(0x1e2)) * parseInt(_0x451b7d(0x1f1)) + parseInt(_0x451b7d(0x1ee)) + parseInt(_0x451b7d(0x1ea)) * -parseInt(_0x451b7d(0x1f9)) + -parseInt(_0x451b7d(0x1ef)) + -parseInt(_0x451b7d(0x1ec)) * parseInt(_0x451b7d(0x1f0)) + parseInt(_0x451b7d(0x1f8));
            if (_0xe0796 === _0x1fa8b2)
                break;
            else
                _0x3ab8b3['push'](_0x3ab8b3['shift']());
        } catch (_0x1b9527) {
            _0x3ab8b3['push'](_0x3ab8b3['shift']());
        }
    }
}(a133_0x34ea, 0xc6ad9), describe('PrettyPrinter\x20(HTML\x20Dependent)', function () {
    var _0x1dce8e = a133_0x5c83;
    it(_0x1dce8e(0x1e1), function () {
        var _0x3cb546 = _0x1dce8e, _0x6a7ba2 = document[_0x3cb546(0x1fb)](''), _0xf4226b = jasmineUnderTest['makePrettyPrinter']();
        expect(_0xf4226b(_0x6a7ba2))[_0x3cb546(0x1e0)](_0x3cb546(0x1df)), expect(_0xf4226b({ 'foo': _0x6a7ba2 }))[_0x3cb546(0x1e0)](_0x3cb546(0x1ed));
    }), it('should\x20stringify\x20empty\x20HTML\x20elements\x20as\x20their\x20opening\x20tags', function () {
        var _0x373c0f = _0x1dce8e, _0x403cdf = document[_0x373c0f(0x1de)]('div'), _0x199dda = jasmineUnderTest['makePrettyPrinter']();
        _0x403cdf[_0x373c0f(0x1fa)] = 'foo', expect(_0x199dda(_0x403cdf))[_0x373c0f(0x1e0)](_0x373c0f(0x1f7));
    }), it(_0x1dce8e(0x1f5), function () {
        var _0x4cb212 = _0x1dce8e, _0x44d943 = jasmineUnderTest[_0x4cb212(0x1e7)](), _0x5e7f7c = document[_0x4cb212(0x1de)](_0x4cb212(0x1f3));
        _0x5e7f7c['className'] = _0x4cb212(0x1f6), _0x5e7f7c['innerHTML'] = _0x4cb212(0x1f4), expect(_0x44d943(_0x5e7f7c))['toEqual'](_0x4cb212(0x1f2));
    }), it(_0x1dce8e(0x1e5), function () {
        var _0x11fd37 = _0x1dce8e;
        if (jasmine['getEnv']()[_0x11fd37(0x1e9)]) {
            var _0x13004c = jasmineUnderTest[_0x11fd37(0x1e7)]();
            try {
                new CustomEvent();
            } catch (_0x2ca985) {
                var _0x5a7bcd = _0x2ca985;
            }
            expect(_0x13004c(_0x5a7bcd))[_0x11fd37(0x1e4)](/Not enough arguments|CustomEvent.*only 0.*passed/);
        }
    }), it('should\x20stringify\x20HTML\x20element\x20with\x20text\x20and\x20attributes', function () {
        var _0x42c89f = _0x1dce8e, _0x2889da = jasmineUnderTest[_0x42c89f(0x1e7)](), _0x169b4c = document[_0x42c89f(0x1de)](_0x42c89f(0x1f3));
        _0x169b4c['setAttribute'](_0x42c89f(0x1eb), _0x42c89f(0x1f6)), _0x169b4c[_0x42c89f(0x1e8)] = _0x42c89f(0x1f6), expect(_0x2889da(_0x169b4c))['toEqual'](_0x42c89f(0x1dd));
    });
}));