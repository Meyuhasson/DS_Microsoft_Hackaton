var a13_0x5f59 = [
    'currentlyPlayingSong',
    'play',
    'toBeFalsy',
    'persistFavoriteStatus',
    '22343GZvgLJ',
    'makeFavorite',
    'should\x20indicate\x20that\x20the\x20song\x20is\x20currently\x20paused',
    'not',
    'toBeTruthy',
    '209201FVuMQX',
    'tells\x20the\x20current\x20song\x20if\x20the\x20user\x20has\x20made\x20it\x20a\x20favorite',
    'toThrowError',
    'should\x20be\x20able\x20to\x20play\x20a\x20Song',
    '../../lib/jasmine_examples/Player',
    '../../lib/jasmine_examples/Song',
    'pause',
    'Player',
    'toBePlaying',
    '1193764RSUgAe',
    '1017398GTGNOp',
    '2744949dzMgmh',
    '185359sSDAyZ',
    'toEqual',
    '453040HaHeNh',
    'should\x20throw\x20an\x20exception\x20if\x20song\x20is\x20already\x20playing',
    'should\x20be\x20possible\x20to\x20resume',
    'resume',
    '6MuuswO',
    '22yslDeh',
    'when\x20song\x20has\x20been\x20paused'
];
var a13_0x5a92ad = a13_0x3a8a;
function a13_0x3a8a(_0x334cff, _0x2dcf0c) {
    return a13_0x3a8a = function (_0x5f5984, _0x3a8abe) {
        _0x5f5984 = _0x5f5984 - 0x1f0;
        var _0x31eb28 = a13_0x5f59[_0x5f5984];
        return _0x31eb28;
    }, a13_0x3a8a(_0x334cff, _0x2dcf0c);
}
(function (_0x7e220, _0xdf3c3f) {
    var _0x5c62de = a13_0x3a8a;
    while (!![]) {
        try {
            var _0x589ed7 = parseInt(_0x5c62de(0x1fd)) + -parseInt(_0x5c62de(0x1fc)) + parseInt(_0x5c62de(0x206)) * -parseInt(_0x5c62de(0x20c)) + parseInt(_0x5c62de(0x1f3)) + -parseInt(_0x5c62de(0x201)) + -parseInt(_0x5c62de(0x205)) * parseInt(_0x5c62de(0x1ff)) + parseInt(_0x5c62de(0x1fe));
            if (_0x589ed7 === _0xdf3c3f)
                break;
            else
                _0x7e220['push'](_0x7e220['shift']());
        } catch (_0x591be3) {
            _0x7e220['push'](_0x7e220['shift']());
        }
    }
}(a13_0x5f59, 0xb0094), describe(a13_0x5a92ad(0x1fa), function () {
    var _0xd8a53c = a13_0x5a92ad, _0x1885b4 = require(_0xd8a53c(0x1f7)), _0x59d6d2 = require(_0xd8a53c(0x1f8)), _0x4964d6, _0x2f4d53;
    beforeEach(function () {
        _0x4964d6 = new _0x1885b4(), _0x2f4d53 = new _0x59d6d2();
    }), it(_0xd8a53c(0x1f6), function () {
        var _0x20010b = _0xd8a53c;
        _0x4964d6['play'](_0x2f4d53), expect(_0x4964d6[_0x20010b(0x208)])[_0x20010b(0x200)](_0x2f4d53), expect(_0x4964d6)[_0x20010b(0x1fb)](_0x2f4d53);
    }), describe(_0xd8a53c(0x207), function () {
        var _0xa09b70 = _0xd8a53c;
        beforeEach(function () {
            var _0x2f122e = a13_0x3a8a;
            _0x4964d6[_0x2f122e(0x209)](_0x2f4d53), _0x4964d6[_0x2f122e(0x1f9)]();
        }), it(_0xa09b70(0x1f0), function () {
            var _0x2a0151 = _0xa09b70;
            expect(_0x4964d6['isPlaying'])[_0x2a0151(0x20a)](), expect(_0x4964d6)[_0x2a0151(0x1f1)][_0x2a0151(0x1fb)](_0x2f4d53);
        }), it(_0xa09b70(0x203), function () {
            var _0x682da1 = _0xa09b70;
            _0x4964d6[_0x682da1(0x204)](), expect(_0x4964d6['isPlaying'])[_0x682da1(0x1f2)](), expect(_0x4964d6[_0x682da1(0x208)])['toEqual'](_0x2f4d53);
        });
    }), it(_0xd8a53c(0x1f4), function () {
        var _0xcda042 = _0xd8a53c;
        spyOn(_0x2f4d53, _0xcda042(0x20b)), _0x4964d6[_0xcda042(0x209)](_0x2f4d53), _0x4964d6[_0xcda042(0x20d)](), expect(_0x2f4d53[_0xcda042(0x20b)])['toHaveBeenCalledWith'](!![]);
    }), describe('#resume', function () {
        var _0x1f63bb = _0xd8a53c;
        it(_0x1f63bb(0x202), function () {
            var _0x290af0 = _0x1f63bb;
            _0x4964d6['play'](_0x2f4d53), expect(function () {
                _0x4964d6['resume']();
            })[_0x290af0(0x1f5)]('song\x20is\x20already\x20playing');
        });
    });
}));