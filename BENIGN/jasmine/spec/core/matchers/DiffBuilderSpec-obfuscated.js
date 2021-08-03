var a74_0x3d77 = [
    'diffFormatter',
    '[thing\x20with\x20a=',
    'DiffBuilder',
    'withPath',
    'Expected\x20$.foo\x20=\x20Object({\x20x:\x20\x27actual\x27\x20})\x20to\x20equal\x20Object({\x20x:\x20\x27expected\x27\x20}).',
    'foo',
    '833548bvkXuv',
    'uses\x20custom\x20object\x20formatters\x20on\x20non\x20leaf\x20nodes',
    'actual',
    'builds\x20diffs\x20involving\x20asymmetric\x20equality\x20testers\x20that\x20implement\x20valuesForDiff_\x20below\x20the\x20root',
    '21XNVNRK',
    'uses\x20the\x20injected\x20pretty-printer',
    'anything',
    '41294SXHROw',
    'expected',
    '\x20disturbing.\x20(was\x20',
    'Expected\x20Object({\x20x:\x20\x27actual\x27\x20})\x20to\x20equal\x20Object({\x20x:\x20\x27expected\x27\x20}).',
    'yes',
    'createSpy',
    'setRoots',
    '2NlVNTQ',
    '447018etgDDR',
    'hasOwnProperty',
    'getMessage',
    '1430788lTqwBi',
    '27557mxwDCm',
    'toHaveBeenCalledWith',
    'I\x20find\x20your\x20lack\x20of\x20foo\x20disturbing.\x20(was\x20bar,\x20at\x20$.x)',
    'toEqual',
    'prints\x20the\x20path\x20at\x20which\x20the\x20difference\x20was\x20found',
    ',\x20b=',
    'allows\x20customization\x20of\x20the\x20message',
    'Expected\x20$.x.foo\x20=\x201\x20to\x20equal\x202.\x0a',
    'I\x20find\x20your\x20lack\x20of\x20',
    'stringify',
    'bar',
    'baz',
    'Expected\x20$.baz\x20=\x20undefined\x20to\x20equal\x203.',
    '1OHpaKW',
    '1582193ubChmO',
    'Expected\x20$[0].foo\x20=\x20[thing\x20with\x20a=1,\x20b={\x22x\x22:42}]\x20to\x20equal\x20[thing\x20with\x20a=1,\x20b={\x22x\x22:43}].\x0a',
    'Expected\x20[number:5]\x20to\x20equal\x20[number:4].',
    'Expected\x20$.bar\x20=\x203\x20to\x20equal\x204.',
    'prints\x20multiple\x20messages,\x20separated\x20by\x20newlines',
    '1124000KjmTmP',
    'customFormat_',
    ',\x20at\x20',
    '[number:',
    'objectContaining',
    'recordMismatch',
    'makePrettyPrinter',
    'Expected\x20$.foo\x20=\x201\x20to\x20equal\x202.\x0a'
];
var a74_0x3c0510 = a74_0x38ca;
function a74_0x38ca(_0x12a041, _0x252af8) {
    return a74_0x38ca = function (_0x3d7742, _0x38ca34) {
        _0x3d7742 = _0x3d7742 - 0x71;
        var _0xdbaacc = a74_0x3d77[_0x3d7742];
        return _0xdbaacc;
    }, a74_0x38ca(_0x12a041, _0x252af8);
}
(function (_0x35759c, _0x3e2530) {
    var _0x12f610 = a74_0x38ca;
    while (!![]) {
        try {
            var _0x3141b4 = parseInt(_0x12f610(0x75)) * parseInt(_0x12f610(0x83)) + -parseInt(_0x12f610(0x95)) * -parseInt(_0x12f610(0x7c)) + -parseInt(_0x12f610(0x84)) + -parseInt(_0x12f610(0x9b)) + parseInt(_0x12f610(0x79)) * parseInt(_0x12f610(0x88)) + -parseInt(_0x12f610(0x87)) + parseInt(_0x12f610(0x96));
            if (_0x3141b4 === _0x3e2530)
                break;
            else
                _0x35759c['push'](_0x35759c['shift']());
        } catch (_0x5864b8) {
            _0x35759c['push'](_0x35759c['shift']());
        }
    }
}(a74_0x3d77, 0xd3c92), describe(a74_0x3c0510(0x71), function () {
    var _0x44ef9d = a74_0x3c0510;
    it('records\x20the\x20actual\x20and\x20expected\x20objects', function () {
        var _0x5ac138 = a74_0x38ca, _0x57fda7 = jasmineUnderTest[_0x5ac138(0x71)]();
        _0x57fda7['setRoots']({ 'x': 'actual' }, { 'x': _0x5ac138(0x7d) }), _0x57fda7[_0x5ac138(0xa0)](), expect(_0x57fda7[_0x5ac138(0x86)]())[_0x5ac138(0x8b)](_0x5ac138(0x7f));
    }), it(_0x44ef9d(0x8c), function () {
        var _0x5ac9ad = _0x44ef9d, _0x20426d = jasmineUnderTest[_0x5ac9ad(0x71)]();
        _0x20426d[_0x5ac9ad(0x82)]({ 'foo': { 'x': _0x5ac9ad(0x77) } }, { 'foo': { 'x': 'expected' } }), _0x20426d[_0x5ac9ad(0x72)]('foo', function () {
            var _0x285020 = _0x5ac9ad;
            _0x20426d[_0x285020(0xa0)]();
        }), expect(_0x20426d['getMessage']())[_0x5ac9ad(0x8b)](_0x5ac9ad(0x73));
    }), it(_0x44ef9d(0x9a), function () {
        var _0x24a381 = _0x44ef9d, _0x3e16a8 = jasmineUnderTest[_0x24a381(0x71)]();
        _0x3e16a8[_0x24a381(0x82)]({
            'foo': 0x1,
            'bar': 0x3
        }, {
            'foo': 0x2,
            'bar': 0x4
        }), _0x3e16a8[_0x24a381(0x72)](_0x24a381(0x74), function () {
            var _0x38471c = _0x24a381;
            _0x3e16a8[_0x38471c(0xa0)]();
        }), _0x3e16a8[_0x24a381(0x72)](_0x24a381(0x92), function () {
            var _0x19c9ec = _0x24a381;
            _0x3e16a8[_0x19c9ec(0xa0)]();
        });
        var _0x4ce76a = _0x24a381(0xa2) + _0x24a381(0x99);
        expect(_0x3e16a8[_0x24a381(0x86)]())[_0x24a381(0x8b)](_0x4ce76a);
    }), it(_0x44ef9d(0x8e), function () {
        var _0x5d845f = _0x44ef9d, _0x144c96 = jasmineUnderTest[_0x5d845f(0x71)]();
        _0x144c96[_0x5d845f(0x82)]({ 'x': _0x5d845f(0x92) }, { 'x': _0x5d845f(0x74) });
        function _0x353a1d(_0x27f942, _0x2fd094, _0x1ca3b1) {
            var _0x62848c = _0x5d845f;
            return _0x62848c(0x90) + _0x2fd094 + _0x62848c(0x7e) + _0x27f942 + _0x62848c(0x9d) + _0x1ca3b1 + ')';
        }
        _0x144c96['withPath']('x', function () {
            var _0x475683 = _0x5d845f;
            _0x144c96[_0x475683(0xa0)](_0x353a1d);
        }), expect(_0x144c96[_0x5d845f(0x86)]())[_0x5d845f(0x8b)](_0x5d845f(0x8a));
    }), it(_0x44ef9d(0x7a), function () {
        var _0x22fe28 = _0x44ef9d, _0x1ca6af = function (_0x2a48c1) {
                return '|' + _0x2a48c1 + '|';
            }, _0x17a1b3 = jasmineUnderTest[_0x22fe28(0x71)]({ 'prettyPrinter': _0x1ca6af });
        _0x1ca6af[_0x22fe28(0x9c)] = function () {
        }, _0x17a1b3[_0x22fe28(0x82)]({ 'foo': _0x22fe28(0x77) }, { 'foo': _0x22fe28(0x7d) }), _0x17a1b3[_0x22fe28(0x72)]('foo', function () {
            var _0x3d624e = _0x22fe28;
            _0x17a1b3[_0x3d624e(0xa0)]();
        }), expect(_0x17a1b3['getMessage']())[_0x22fe28(0x8b)]('Expected\x20$.foo\x20=\x20|actual|\x20to\x20equal\x20|expected|.');
    }), it('passes\x20the\x20injected\x20pretty-printer\x20to\x20the\x20diff\x20formatter', function () {
        var _0x3548b0 = _0x44ef9d, _0x17555f = jasmine[_0x3548b0(0x81)](_0x3548b0(0xa3)), _0x590349 = function () {
            }, _0x34d931 = jasmineUnderTest[_0x3548b0(0x71)]({ 'prettyPrinter': _0x590349 });
        _0x590349[_0x3548b0(0x9c)] = function () {
        }, _0x34d931[_0x3548b0(0x82)]({ 'x': _0x3548b0(0x92) }, { 'x': _0x3548b0(0x74) }), _0x34d931[_0x3548b0(0x72)]('x', function () {
            var _0x124156 = _0x3548b0;
            _0x34d931[_0x124156(0xa0)](_0x17555f);
        }), _0x34d931['getMessage'](), expect(_0x17555f)[_0x3548b0(0x89)]('bar', _0x3548b0(0x74), jasmine[_0x3548b0(0x7b)](), _0x590349);
    }), it('uses\x20custom\x20object\x20formatters\x20on\x20leaf\x20nodes', function () {
        var _0x5a6039 = _0x44ef9d, _0x1f5f35 = function (_0x183508) {
                var _0x16d401 = a74_0x38ca;
                if (typeof _0x183508 === 'number')
                    return _0x16d401(0x9e) + _0x183508 + ']';
            };
        prettyPrinter = jasmineUnderTest['makePrettyPrinter']([_0x1f5f35]);
        var _0x273fc8 = new jasmineUnderTest[(_0x5a6039(0x71))]({ 'prettyPrinter': prettyPrinter });
        _0x273fc8[_0x5a6039(0x82)](0x5, 0x4), _0x273fc8['recordMismatch'](), expect(_0x273fc8[_0x5a6039(0x86)]())[_0x5a6039(0x8b)](_0x5a6039(0x98));
    }), it(_0x44ef9d(0x76), function () {
        var _0x46951f = _0x44ef9d, _0x17a47e = function (_0x5a4b37) {
                var _0x3ace87 = a74_0x38ca;
                if (_0x5a4b37[_0x3ace87(0x85)]('a'))
                    return _0x3ace87(0xa4) + _0x5a4b37['a'] + _0x3ace87(0x8d) + JSON[_0x3ace87(0x91)](_0x5a4b37['b']) + ']';
            };
        prettyPrinter = jasmineUnderTest['makePrettyPrinter']([_0x17a47e]);
        var _0x36fe2c = new jasmineUnderTest[(_0x46951f(0x71))]({ 'prettyPrinter': prettyPrinter }), _0x4da1e6 = _0x46951f(0x97) + 'Expected\x20$[0].bar\x20=\x20\x27yes\x27\x20to\x20equal\x20\x27no\x27.';
        _0x36fe2c[_0x46951f(0x82)]([{
                'foo': {
                    'a': 0x1,
                    'b': { 'x': 0x2a }
                },
                'bar': _0x46951f(0x80)
            }], [{
                'foo': {
                    'a': 0x1,
                    'b': { 'x': 0x2b }
                },
                'bar': 'no'
            }]), _0x36fe2c['withPath'](0x0, function () {
            var _0xf0565b = _0x46951f;
            _0x36fe2c[_0xf0565b(0x72)](_0xf0565b(0x74), function () {
                var _0x3848bc = _0xf0565b;
                _0x36fe2c[_0x3848bc(0x72)]('b', function () {
                    var _0x3ff4d3 = _0x3848bc;
                    _0x36fe2c[_0x3ff4d3(0x72)]('x', function () {
                        var _0x432764 = _0x3ff4d3;
                        _0x36fe2c[_0x432764(0xa0)]();
                    });
                });
            }), _0x36fe2c[_0xf0565b(0x72)](_0xf0565b(0x92), function () {
                var _0xaa2273 = _0xf0565b;
                _0x36fe2c[_0xaa2273(0xa0)]();
            });
        }), expect(_0x36fe2c['getMessage']())[_0x46951f(0x8b)](_0x4da1e6);
    }), it('builds\x20diffs\x20involving\x20asymmetric\x20equality\x20testers\x20that\x20implement\x20valuesForDiff_\x20at\x20the\x20root', function () {
        var _0x1ba659 = _0x44ef9d, _0x2a89c0 = jasmineUnderTest['makePrettyPrinter']([]), _0x266bda = new jasmineUnderTest[(_0x1ba659(0x71))]({ 'prettyPrinter': _0x2a89c0 }), _0x52787c = 'Expected\x20$.foo\x20=\x201\x20to\x20equal\x202.\x0a' + _0x1ba659(0x94);
        _0x266bda[_0x1ba659(0x82)]({
            'foo': 0x1,
            'bar': 0x2
        }, jasmine[_0x1ba659(0x9f)]({
            'foo': 0x2,
            'baz': 0x3
        })), _0x266bda[_0x1ba659(0x72)]('foo', function () {
            var _0x520475 = _0x1ba659;
            _0x266bda[_0x520475(0xa0)]();
        }), _0x266bda[_0x1ba659(0x72)](_0x1ba659(0x93), function () {
            var _0x317c71 = _0x1ba659;
            _0x266bda[_0x317c71(0xa0)]();
        }), expect(_0x266bda['getMessage']())[_0x1ba659(0x8b)](_0x52787c);
    }), it(_0x44ef9d(0x78), function () {
        var _0x121394 = _0x44ef9d, _0x12f9c1 = jasmineUnderTest[_0x121394(0xa1)]([]), _0x1b50c4 = new jasmineUnderTest[(_0x121394(0x71))]({ 'prettyPrinter': _0x12f9c1 }), _0x6572a3 = _0x121394(0x8f) + 'Expected\x20$.x.baz\x20=\x20undefined\x20to\x20equal\x203.';
        _0x1b50c4[_0x121394(0x82)]({
            'x': {
                'foo': 0x1,
                'bar': 0x2
            }
        }, {
            'x': jasmine[_0x121394(0x9f)]({
                'foo': 0x2,
                'baz': 0x3
            })
        }), _0x1b50c4[_0x121394(0x72)]('x', function () {
            var _0x539389 = _0x121394;
            _0x1b50c4[_0x539389(0x72)](_0x539389(0x74), function () {
                _0x1b50c4['recordMismatch']();
            }), _0x1b50c4[_0x539389(0x72)](_0x539389(0x93), function () {
                var _0x2f59cf = _0x539389;
                _0x1b50c4[_0x2f59cf(0xa0)]();
            });
        }), expect(_0x1b50c4['getMessage']())['toEqual'](_0x6572a3);
    });
}));