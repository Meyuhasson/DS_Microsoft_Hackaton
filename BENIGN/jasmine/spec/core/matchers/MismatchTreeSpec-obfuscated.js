var a75_0x33ca = [
    'toHaveBeenCalled',
    'not',
    '1579Xabrps',
    'toEqual',
    'length',
    '1xkiQyX',
    'path',
    '31pgnWAM',
    'toHaveBeenCalledWith',
    '#traverse',
    'traverse',
    '1392410VzXYMO',
    'toBe',
    'When\x20the\x20path\x20is\x20not\x20empty',
    'stores\x20the\x20formatter\x20on\x20only\x20the\x20target\x20node',
    'MismatchTree',
    'formatter',
    'ObjectPath',
    '447107vNlkEb',
    'isMismatch',
    'push',
    '25505NjNQvX',
    'visit',
    'calls\x20the\x20callback\x20for\x20all\x20nodes\x20that\x20are\x20or\x20contain\x20mismatches',
    'child',
    'visits\x20children\x20in\x20the\x20order\x20they\x20were\x20recorded',
    'and',
    '2uPwART',
    '1XXQqVP',
    'returnValue',
    '2Iaebta',
    '42612omOFYQ',
    'components',
    'depth',
    'does\x20not\x20call\x20the\x20callback\x20if\x20there\x20are\x20no\x20mismatches',
    'toBeFalsy',
    '194ryrsQh',
    '14412FtSmFE',
    'createSpy',
    '387769WllicK',
    'add',
    'flags\x20the\x20node\x20as\x20mismatched'
];
function a75_0x57ef(_0x2f3fba, _0x41d314) {
    return a75_0x57ef = function (_0x33cadb, _0x57ef9f) {
        _0x33cadb = _0x33cadb - 0xc0;
        var _0x5b8f15 = a75_0x33ca[_0x33cadb];
        return _0x5b8f15;
    }, a75_0x57ef(_0x2f3fba, _0x41d314);
}
(function (_0x38c29b, _0x210c2e) {
    var _0x48f9d6 = a75_0x57ef;
    while (!![]) {
        try {
            var _0x11d386 = parseInt(_0x48f9d6(0xe5)) * parseInt(_0x48f9d6(0xe8)) + parseInt(_0x48f9d6(0xd4)) + parseInt(_0x48f9d6(0xc4)) * -parseInt(_0x48f9d6(0xd0)) + parseInt(_0x48f9d6(0xc6)) * parseInt(_0x48f9d6(0xce)) + parseInt(_0x48f9d6(0xc3)) * parseInt(_0x48f9d6(0xcb)) + -parseInt(_0x48f9d6(0xe4)) * parseInt(_0x48f9d6(0xdb)) + -parseInt(_0x48f9d6(0xde)) * -parseInt(_0x48f9d6(0xe7));
            if (_0x11d386 === _0x210c2e)
                break;
            else
                _0x38c29b['push'](_0x38c29b['shift']());
        } catch (_0x552a6c) {
            _0x38c29b['push'](_0x38c29b['shift']());
        }
    }
}(a75_0x33ca, 0xccde5), describe('MismatchTree', function () {
    var _0x2fd44e = a75_0x57ef;
    describe('#add', function () {
        var _0xe81778 = a75_0x57ef;
        describe('When\x20the\x20path\x20is\x20empty', function () {
            it('flags\x20the\x20root\x20node\x20as\x20mismatched', function () {
                var _0x2157bc = a75_0x57ef, _0xae5bfd = new jasmineUnderTest[(_0x2157bc(0xd8))]();
                _0xae5bfd[_0x2157bc(0xc7)](new jasmineUnderTest[(_0x2157bc(0xda))]([])), expect(_0xae5bfd[_0x2157bc(0xdc)])['toBe'](!![]);
            });
        }), describe(_0xe81778(0xd6), function () {
            var _0x5b0b79 = _0xe81778;
            it(_0x5b0b79(0xc8), function () {
                var _0x27227f = _0x5b0b79, _0xe3d798 = new jasmineUnderTest[(_0x27227f(0xd8))]();
                _0xe3d798[_0x27227f(0xc7)](new jasmineUnderTest['ObjectPath']([
                    'a',
                    'b'
                ])), expect(_0xe3d798['child']('a')['child']('b')['isMismatch'])['toBe'](!![]);
            }), it('does\x20not\x20flag\x20ancestors\x20as\x20mismatched', function () {
                var _0xe78d37 = _0x5b0b79, _0x6ce5a = new jasmineUnderTest['MismatchTree']();
                _0x6ce5a['add'](new jasmineUnderTest[(_0xe78d37(0xda))]([
                    'a',
                    'b'
                ])), expect(_0x6ce5a[_0xe78d37(0xdc)])[_0xe78d37(0xd5)](![]), expect(_0x6ce5a[_0xe78d37(0xe1)]('a')[_0xe78d37(0xdc)])[_0xe78d37(0xd5)](![]);
            });
        }), it(_0xe81778(0xd7), function () {
            var _0x4b83cd = _0xe81778, _0x3e3579 = new jasmineUnderTest[(_0x4b83cd(0xd8))]();
            _0x3e3579[_0x4b83cd(0xc7)](new jasmineUnderTest[(_0x4b83cd(0xda))]([
                'a',
                'b'
            ]), _0x4ecb20), expect(_0x3e3579[_0x4b83cd(0xd9)])['toBeFalsy'](), expect(_0x3e3579[_0x4b83cd(0xe1)]('a')['formatter'])[_0x4b83cd(0xc2)](), expect(_0x3e3579[_0x4b83cd(0xe1)]('a')[_0x4b83cd(0xe1)]('b')[_0x4b83cd(0xd9)])['toBe'](_0x4ecb20);
        }), it('stores\x20the\x20path\x20to\x20the\x20node', function () {
            var _0x1aa7bd = _0xe81778, _0x1fb132 = new jasmineUnderTest['MismatchTree']();
            _0x1fb132[_0x1aa7bd(0xc7)](new jasmineUnderTest[(_0x1aa7bd(0xda))]([
                'a',
                'b'
            ]), _0x4ecb20), expect(_0x1fb132[_0x1aa7bd(0xe1)]('a')[_0x1aa7bd(0xe1)]('b')[_0x1aa7bd(0xcf)][_0x1aa7bd(0xe9)])[_0x1aa7bd(0xcc)]([
                'a',
                'b'
            ]);
        });
    }), describe(_0x2fd44e(0xd2), function () {
        var _0x402999 = _0x2fd44e;
        it(_0x402999(0xe0), function () {
            var _0x555078 = _0x402999, _0x5c5824 = new jasmineUnderTest[(_0x555078(0xd8))]();
            _0x5c5824[_0x555078(0xc7)](new jasmineUnderTest[(_0x555078(0xda))]([
                'a',
                'b'
            ]), _0x4ecb20), _0x5c5824['add'](new jasmineUnderTest[(_0x555078(0xda))](['c']));
            var _0x3d1dbc = jasmine[_0x555078(0xc5)](_0x555078(0xdf))[_0x555078(0xe3)][_0x555078(0xe6)](!![]);
            _0x5c5824[_0x555078(0xd3)](_0x3d1dbc), expect(_0x3d1dbc)[_0x555078(0xd1)](new jasmineUnderTest['ObjectPath']([]), ![], undefined), expect(_0x3d1dbc)[_0x555078(0xd1)](new jasmineUnderTest['ObjectPath'](['a']), ![], undefined), expect(_0x3d1dbc)[_0x555078(0xd1)](new jasmineUnderTest[(_0x555078(0xda))]([
                'a',
                'b'
            ]), !![], _0x4ecb20), expect(_0x3d1dbc)['toHaveBeenCalledWith'](new jasmineUnderTest[(_0x555078(0xda))](['c']), !![], undefined);
        }), it(_0x402999(0xc1), function () {
            var _0x280925 = _0x402999, _0x2da7d0 = new jasmineUnderTest['MismatchTree'](), _0x179715 = jasmine[_0x280925(0xc5)](_0x280925(0xdf));
            _0x2da7d0[_0x280925(0xd3)](_0x179715), expect(_0x179715)[_0x280925(0xca)][_0x280925(0xc9)]();
        }), it('visits\x20parents\x20before\x20children', function () {
            var _0x1d8bc4 = _0x402999, _0x177395 = new jasmineUnderTest[(_0x1d8bc4(0xd8))]();
            _0x177395[_0x1d8bc4(0xc7)](new jasmineUnderTest[(_0x1d8bc4(0xda))]([
                'a',
                'b'
            ]));
            var _0x1425b9 = [];
            _0x177395[_0x1d8bc4(0xd3)](function (_0xd9163d) {
                var _0x51959c = _0x1d8bc4;
                return _0x1425b9[_0x51959c(0xdd)](_0xd9163d), !![];
            }), expect(_0x1425b9)['toEqual']([
                new jasmineUnderTest[(_0x1d8bc4(0xda))]([]),
                new jasmineUnderTest[(_0x1d8bc4(0xda))](['a']),
                new jasmineUnderTest['ObjectPath']([
                    'a',
                    'b'
                ])
            ]);
        }), it(_0x402999(0xe2), function () {
            var _0x955819 = _0x402999, _0x58efe3 = new jasmineUnderTest['MismatchTree']();
            _0x58efe3[_0x955819(0xc7)](new jasmineUnderTest[(_0x955819(0xda))]([_0x955819(0xcd)])), _0x58efe3[_0x955819(0xc7)](new jasmineUnderTest[(_0x955819(0xda))]([0x1]));
            var _0xd3e425 = [];
            _0x58efe3['traverse'](function (_0x5f5ad8) {
                var _0x1fd3c4 = _0x955819;
                return _0xd3e425[_0x1fd3c4(0xdd)](_0x5f5ad8), !![];
            }), expect(_0xd3e425)['toEqual']([
                new jasmineUnderTest['ObjectPath']([]),
                new jasmineUnderTest[(_0x955819(0xda))]([_0x955819(0xcd)]),
                new jasmineUnderTest['ObjectPath']([0x1])
            ]);
        }), it('does\x20not\x20visit\x20children\x20if\x20the\x20callback\x20returns\x20falsy', function () {
            var _0x1eda6e = _0x402999, _0x513211 = new jasmineUnderTest[(_0x1eda6e(0xd8))]();
            _0x513211[_0x1eda6e(0xc7)](new jasmineUnderTest['ObjectPath']([
                'a',
                'b'
            ]));
            var _0x9f97e3 = [];
            _0x513211[_0x1eda6e(0xd3)](function (_0x9ae0b8) {
                var _0x22e182 = _0x1eda6e;
                return _0x9f97e3['push'](_0x9ae0b8), _0x9ae0b8[_0x22e182(0xc0)]() === 0x0;
            }), expect(_0x9f97e3)[_0x1eda6e(0xcc)]([
                new jasmineUnderTest[(_0x1eda6e(0xda))]([]),
                new jasmineUnderTest[(_0x1eda6e(0xda))](['a'])
            ]);
        });
    });
    function _0x4ecb20() {
    }
}));