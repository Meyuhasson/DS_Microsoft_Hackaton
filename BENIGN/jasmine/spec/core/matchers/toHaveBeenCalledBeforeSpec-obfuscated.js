var a105_0x23c2 = [
    'toHaveBeenCalledBefore',
    '904163Zgvnxa',
    '1TCTdVW',
    'pass',
    '550997JLcgaq',
    'throws\x20an\x20exception\x20when\x20the\x20expected\x20is\x20not\x20a\x20spy',
    'passes\x20when\x20the\x20actual\x20is\x20called\x20before\x20the\x20expected',
    '1rHaDCo',
    'createSpy',
    'fails\x20when\x20the\x20expected\x20is\x20called\x20before\x20and\x20after\x20the\x20actual',
    '985491KzTuBT',
    'Expected\x20latest\x20call\x20to\x20spy\x20first\x20spy\x20to\x20have\x20been\x20called\x20before\x20first\x20call\x20to\x20spy\x20second\x20spy\x20(no\x20interleaved\x20calls)',
    'makePrettyPrinter',
    'fails\x20when\x20the\x20actual\x20was\x20not\x20called',
    '1sBTXxw',
    'first\x20spy',
    'toEqual',
    'compare',
    '1WOPILa',
    'second\x20spy',
    'Spy',
    'message',
    'fails\x20when\x20the\x20actual\x20is\x20called\x20before\x20and\x20after\x20the\x20expected',
    '453942PAvRkP',
    'Expected\x20spy\x20first\x20spy\x20to\x20not\x20have\x20been\x20called\x20before\x20spy\x20second\x20spy,\x20but\x20it\x20was',
    'Expected\x20first\x20call\x20to\x20spy\x20second\x20spy\x20to\x20have\x20been\x20called\x20after\x20latest\x20call\x20to\x20spy\x20first\x20spy\x20(no\x20interleaved\x20calls)',
    '1168799IHsyph',
    'a\x20spy',
    'fails\x20when\x20the\x20expected\x20was\x20not\x20called',
    '67486mASJVx',
    'Expected\x20spy\x20first\x20spy\x20to\x20have\x20been\x20called\x20before\x20spy\x20second\x20spy',
    'Env',
    'throws\x20an\x20exception\x20when\x20the\x20actual\x20is\x20not\x20a\x20spy',
    '1047271INLYSE',
    'toMatch',
    'toBe',
    'matchers',
    'toThrowError'
];
var a105_0x5d00aa = a105_0x22f8;
function a105_0x22f8(_0x11d0b3, _0x2cd1f3) {
    return a105_0x22f8 = function (_0x23c230, _0x22f86a) {
        _0x23c230 = _0x23c230 - 0xc0;
        var _0x3a1cb1 = a105_0x23c2[_0x23c230];
        return _0x3a1cb1;
    }, a105_0x22f8(_0x11d0b3, _0x2cd1f3);
}
(function (_0x420c6d, _0x22b726) {
    var _0x44e76a = a105_0x22f8;
    while (!![]) {
        try {
            var _0x41795d = -parseInt(_0x44e76a(0xd0)) + -parseInt(_0x44e76a(0xca)) * -parseInt(_0x44e76a(0xe1)) + -parseInt(_0x44e76a(0xdd)) * -parseInt(_0x44e76a(0xd3)) + parseInt(_0x44e76a(0xd9)) + parseInt(_0x44e76a(0xd6)) * -parseInt(_0x44e76a(0xc3)) + parseInt(_0x44e76a(0xc0)) + parseInt(_0x44e76a(0xd1)) * -parseInt(_0x44e76a(0xc6));
            if (_0x41795d === _0x22b726)
                break;
            else
                _0x420c6d['push'](_0x420c6d['shift']());
        } catch (_0x196630) {
            _0x420c6d['push'](_0x420c6d['shift']());
        }
    }
}(a105_0x23c2, 0xdb0e5), describe(a105_0x5d00aa(0xcf), function () {
    var _0x4badbc = a105_0x5d00aa;
    it(_0x4badbc(0xc9), function () {
        var _0x324c9c = _0x4badbc, _0x5c8984 = jasmineUnderTest[_0x324c9c(0xcd)][_0x324c9c(0xcf)]({ 'pp': jasmineUnderTest[_0x324c9c(0xdb)]() }), _0x171445 = function () {
            }, _0x117ca4 = new jasmineUnderTest[(_0x324c9c(0xc8))]()[_0x324c9c(0xd7)]('a\x20spy');
        expect(function () {
            var _0x4fd9ce = _0x324c9c;
            _0x5c8984[_0x4fd9ce(0xe0)](_0x171445, _0x117ca4);
        })[_0x324c9c(0xce)](Error, /Expected a spy, but got Function./);
    }), it(_0x4badbc(0xd4), function () {
        var _0x5c6fd7 = _0x4badbc, _0x20cfbd = jasmineUnderTest[_0x5c6fd7(0xcd)][_0x5c6fd7(0xcf)]({ 'pp': jasmineUnderTest[_0x5c6fd7(0xdb)]() }), _0x2050ab = new jasmineUnderTest['Env']()['createSpy'](_0x5c6fd7(0xc4)), _0x7d5269 = function () {
            };
        expect(function () {
            var _0x253ed5 = _0x5c6fd7;
            _0x20cfbd[_0x253ed5(0xe0)](_0x2050ab, _0x7d5269);
        })[_0x5c6fd7(0xce)](Error, /Expected a spy, but got Function./);
    }), it(_0x4badbc(0xdc), function () {
        var _0x347048 = _0x4badbc, _0x119526 = jasmineUnderTest['matchers']['toHaveBeenCalledBefore'](), _0x407d0f = new jasmineUnderTest[(_0x347048(0xe3))]('first\x20spy'), _0x35571c = new jasmineUnderTest[(_0x347048(0xe3))]('second\x20spy');
        _0x35571c(), result = _0x119526['compare'](_0x407d0f, _0x35571c), expect(result[_0x347048(0xd2)])[_0x347048(0xcc)](![]), expect(result[_0x347048(0xe4)])[_0x347048(0xcb)](/Expected spy first spy to have been called./);
    }), it(_0x4badbc(0xc5), function () {
        var _0x311c74 = _0x4badbc, _0x4a708f = jasmineUnderTest[_0x311c74(0xcd)][_0x311c74(0xcf)](), _0x3b8f31 = new jasmineUnderTest[(_0x311c74(0xe3))]('first\x20spy'), _0xbcec5a = new jasmineUnderTest[(_0x311c74(0xe3))](_0x311c74(0xe2));
        _0x3b8f31(), result = _0x4a708f[_0x311c74(0xe0)](_0x3b8f31, _0xbcec5a), expect(result['pass'])['toBe'](![]), expect(result[_0x311c74(0xe4)])[_0x311c74(0xcb)](/Expected spy second spy to have been called./);
    }), it('fails\x20when\x20the\x20actual\x20is\x20called\x20after\x20the\x20expected', function () {
        var _0x146454 = _0x4badbc, _0x22ff2b = jasmineUnderTest[_0x146454(0xcd)][_0x146454(0xcf)](), _0x832fea = new jasmineUnderTest[(_0x146454(0xe3))]('first\x20spy'), _0x214188 = new jasmineUnderTest[(_0x146454(0xe3))](_0x146454(0xe2)), _0x53fd94;
        _0x214188(), _0x832fea(), _0x53fd94 = _0x22ff2b[_0x146454(0xe0)](_0x832fea, _0x214188), expect(_0x53fd94[_0x146454(0xd2)])[_0x146454(0xcc)](![]), expect(_0x53fd94['message'])[_0x146454(0xdf)](_0x146454(0xc7));
    }), it(_0x4badbc(0xe5), function () {
        var _0x54a285 = _0x4badbc, _0x53dee1 = jasmineUnderTest['matchers'][_0x54a285(0xcf)](), _0x368946 = new jasmineUnderTest[(_0x54a285(0xe3))]('first\x20spy'), _0x3aa7be = new jasmineUnderTest[(_0x54a285(0xe3))](_0x54a285(0xe2)), _0x48f468;
        _0x368946(), _0x3aa7be(), _0x368946(), _0x48f468 = _0x53dee1[_0x54a285(0xe0)](_0x368946, _0x3aa7be), expect(_0x48f468['pass'])[_0x54a285(0xcc)](![]), expect(_0x48f468[_0x54a285(0xe4)])[_0x54a285(0xdf)](_0x54a285(0xda));
    }), it(_0x4badbc(0xd8), function () {
        var _0x3bfd7e = _0x4badbc, _0x59480f = jasmineUnderTest[_0x3bfd7e(0xcd)][_0x3bfd7e(0xcf)](), _0x533cc9 = new jasmineUnderTest[(_0x3bfd7e(0xe3))](_0x3bfd7e(0xde)), _0x4255b3 = new jasmineUnderTest[(_0x3bfd7e(0xe3))](_0x3bfd7e(0xe2)), _0x4b2a98;
        _0x4255b3(), _0x533cc9(), _0x4255b3(), _0x4b2a98 = _0x59480f[_0x3bfd7e(0xe0)](_0x533cc9, _0x4255b3), expect(_0x4b2a98[_0x3bfd7e(0xd2)])[_0x3bfd7e(0xcc)](![]), expect(_0x4b2a98['message'])[_0x3bfd7e(0xdf)](_0x3bfd7e(0xc2));
    }), it(_0x4badbc(0xd5), function () {
        var _0x44ad83 = _0x4badbc, _0x554b97 = jasmineUnderTest['matchers'][_0x44ad83(0xcf)](), _0x28fa77 = new jasmineUnderTest[(_0x44ad83(0xe3))](_0x44ad83(0xde)), _0x159759 = new jasmineUnderTest[(_0x44ad83(0xe3))](_0x44ad83(0xe2)), _0x3f3e2b;
        _0x28fa77(), _0x159759(), _0x3f3e2b = _0x554b97[_0x44ad83(0xe0)](_0x28fa77, _0x159759), expect(_0x3f3e2b[_0x44ad83(0xd2)])[_0x44ad83(0xcc)](!![]), expect(_0x3f3e2b[_0x44ad83(0xe4)])['toEqual'](_0x44ad83(0xc1));
    });
}));