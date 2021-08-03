var a14_0x310c = [
    '417105uhVJLd',
    '711241bUmAji',
    '2pEojqr',
    'not',
    'should\x20indicate\x20that\x20the\x20song\x20is\x20currently\x20paused',
    'toEqual',
    'persistFavoriteStatus',
    'Player',
    'should\x20be\x20possible\x20to\x20resume',
    '317440RBsNSF',
    'resume',
    'play',
    '80XtbIIE',
    'toBeTruthy',
    'toBePlaying',
    'toHaveBeenCalledWith',
    'isPlaying',
    '899233nwYchV',
    'toBeFalsy',
    'makeFavorite',
    '11506EKwhZS',
    'should\x20be\x20able\x20to\x20play\x20a\x20Song',
    '218588gmtSeD',
    'tells\x20the\x20current\x20song\x20if\x20the\x20user\x20has\x20made\x20it\x20a\x20favorite',
    'when\x20song\x20has\x20been\x20paused',
    '2IYzYov',
    'should\x20throw\x20an\x20exception\x20if\x20song\x20is\x20already\x20playing',
    'currentlyPlayingSong',
    '295975dADndq',
    '#resume',
    'song\x20is\x20already\x20playing'
];
function a14_0x1820(_0x450935, _0x340384) {
    return a14_0x1820 = function (_0x310c2f, _0x182075) {
        _0x310c2f = _0x310c2f - 0x1e8;
        var _0x513e6d = a14_0x310c[_0x310c2f];
        return _0x513e6d;
    }, a14_0x1820(_0x450935, _0x340384);
}
var a14_0x551892 = a14_0x1820;
(function (_0x39e734, _0x39c5d1) {
    var _0xf3f206 = a14_0x1820;
    while (!![]) {
        try {
            var _0x51a2c3 = parseInt(_0xf3f206(0x202)) + -parseInt(_0xf3f206(0x1ec)) + parseInt(_0xf3f206(0x1ed)) + parseInt(_0xf3f206(0x1f8)) * parseInt(_0xf3f206(0x200)) + -parseInt(_0xf3f206(0x205)) * -parseInt(_0xf3f206(0x1e9)) + -parseInt(_0xf3f206(0x1f5)) * parseInt(_0xf3f206(0x1ee)) + -parseInt(_0xf3f206(0x1fd));
            if (_0x51a2c3 === _0x39c5d1)
                break;
            else
                _0x39e734['push'](_0x39e734['shift']());
        } catch (_0x160937) {
            _0x39e734['push'](_0x39e734['shift']());
        }
    }
}(a14_0x310c, 0x77e21), describe(a14_0x551892(0x1f3), function () {
    var _0x5a173e = a14_0x551892, _0x5d18a1, _0xea730a;
    beforeEach(function () {
        _0x5d18a1 = new Player(), _0xea730a = new Song();
    }), it(_0x5a173e(0x201), function () {
        var _0xb6cd4f = _0x5a173e;
        _0x5d18a1[_0xb6cd4f(0x1f7)](_0xea730a), expect(_0x5d18a1[_0xb6cd4f(0x1e8)])[_0xb6cd4f(0x1f1)](_0xea730a), expect(_0x5d18a1)[_0xb6cd4f(0x1fa)](_0xea730a);
    }), describe(_0x5a173e(0x204), function () {
        var _0x1600e7 = _0x5a173e;
        beforeEach(function () {
            _0x5d18a1['play'](_0xea730a), _0x5d18a1['pause']();
        }), it(_0x1600e7(0x1f0), function () {
            var _0x3fd35f = _0x1600e7;
            expect(_0x5d18a1['isPlaying'])[_0x3fd35f(0x1fe)](), expect(_0x5d18a1)[_0x3fd35f(0x1ef)][_0x3fd35f(0x1fa)](_0xea730a);
        }), it(_0x1600e7(0x1f4), function () {
            var _0x18386d = _0x1600e7;
            _0x5d18a1[_0x18386d(0x1f6)](), expect(_0x5d18a1[_0x18386d(0x1fc)])[_0x18386d(0x1f9)](), expect(_0x5d18a1['currentlyPlayingSong'])[_0x18386d(0x1f1)](_0xea730a);
        });
    }), it(_0x5a173e(0x203), function () {
        var _0x26c6be = _0x5a173e;
        spyOn(_0xea730a, _0x26c6be(0x1f2)), _0x5d18a1['play'](_0xea730a), _0x5d18a1[_0x26c6be(0x1ff)](), expect(_0xea730a[_0x26c6be(0x1f2)])[_0x26c6be(0x1fb)](!![]);
    }), describe(_0x5a173e(0x1ea), function () {
        var _0x67edf4 = _0x5a173e;
        it(_0x67edf4(0x206), function () {
            var _0x47d6a6 = _0x67edf4;
            _0x5d18a1[_0x47d6a6(0x1f7)](_0xea730a), expect(function () {
                var _0x51f8a5 = _0x47d6a6;
                _0x5d18a1[_0x51f8a5(0x1f6)]();
            })['toThrowError'](_0x47d6a6(0x1eb));
        });
    });
}));