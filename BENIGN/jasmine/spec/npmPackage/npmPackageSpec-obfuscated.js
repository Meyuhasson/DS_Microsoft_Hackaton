var a137_0x3992 = [
    'toEqual',
    'resolve',
    'toMatch',
    'forEach',
    'has\x20jsFiles',
    'cssFiles',
    'does\x20not\x20have\x20any\x20unexpected\x20files\x20in\x20the\x20root\x20directory',
    'node_boot.js',
    'bootFiles',
    'track',
    '611333LtVlbT',
    'does\x20not\x20have\x20CI\x20config\x20files\x20and\x20scripts',
    'npm\x20pack',
    'tarball',
    'stdout',
    'join',
    'jasmine_favicon.png',
    '1wLUDGJ',
    'toExistInPath',
    'does\x20not\x20have\x20any\x20unexpected\x20files\x20in\x20the\x20package\x20directory',
    'jsFiles',
    'jasmine.css',
    '125mdvJXL',
    'addMatchers',
    'jasmine-html.js',
    'only\x20has\x20images\x20in\x20the\x20images\x20dir',
    'package/lib/jasmine-core.js',
    'boot.js',
    '174397cQenSV',
    'MIT.LICENSE',
    '911629OkgHsx',
    '6CgltgP',
    'temp',
    'images',
    'path',
    'package/images',
    'realpathSync',
    'lib',
    'package/scripts',
    'name',
    'existsSync',
    'toBe',
    'length',
    'has\x20an\x20imagesDir',
    '918578jpeRtA',
    'tmpDir',
    'jasmine-horizontal.png',
    '146776hXRphj',
    'packagedCore',
    'jasmine.js',
    'push',
    'package/lib',
    'mkdirSync',
    'only\x20has\x20JS\x20and\x20CSS\x20files\x20in\x20the\x20lib\x20dir',
    'exec',
    'sort',
    'has\x20bootFiles',
    'package.json',
    'readdirSync',
    'split',
    'jasmine-horizontal.svg',
    'package',
    'toContain',
    'nodeBootFiles',
    'files',
    'has\x20a\x20bootDir',
    '39EghqKz',
    'npm\x20package',
    'imagesDir',
    'code',
    'package/lib/jasmine-core',
    'bootDir',
    '2551MtpdVF',
    '7013pFotRP'
];
function a137_0x3e64(_0x5cbfd1, _0x338b24) {
    return a137_0x3e64 = function (_0x3992a9, _0x3e64d6) {
        _0x3992a9 = _0x3992a9 - 0x187;
        var _0x145fe7 = a137_0x3992[_0x3992a9];
        return _0x145fe7;
    }, a137_0x3e64(_0x5cbfd1, _0x338b24);
}
var a137_0x53fe7f = a137_0x3e64;
(function (_0xd77dd4, _0x16532f) {
    var _0x2a84b6 = a137_0x3e64;
    while (!![]) {
        try {
            var _0x17fdd8 = -parseInt(_0x2a84b6(0x199)) * -parseInt(_0x2a84b6(0x1b1)) + -parseInt(_0x2a84b6(0x19a)) * parseInt(_0x2a84b6(0x193)) + parseInt(_0x2a84b6(0x1ca)) * parseInt(_0x2a84b6(0x1ba)) + parseInt(_0x2a84b6(0x1b9)) + parseInt(_0x2a84b6(0x1b7)) * parseInt(_0x2a84b6(0x1ac)) + -parseInt(_0x2a84b6(0x1a5)) + -parseInt(_0x2a84b6(0x1c7));
            if (_0x17fdd8 === _0x16532f)
                break;
            else
                _0xd77dd4['push'](_0xd77dd4['shift']());
        } catch (_0x34da47) {
            _0xd77dd4['push'](_0xd77dd4['shift']());
        }
    }
}(a137_0x3992, 0x75b5b), describe(a137_0x53fe7f(0x194), function () {
    var _0x44353d = a137_0x53fe7f, _0x49c651 = require('path'), _0x324dc6 = require(_0x44353d(0x1bb))[_0x44353d(0x1a4)](), _0x368879 = require('fs');
    beforeAll(function () {
        var _0x46d6cd = _0x44353d, _0x23fedf = require('shelljs'), _0x3c1ff9 = _0x23fedf[_0x46d6cd(0x187)](_0x46d6cd(0x1a7), { 'silent': !![] });
        this[_0x46d6cd(0x1a8)] = _0x3c1ff9[_0x46d6cd(0x1a9)][_0x46d6cd(0x18c)]('\x0a')[0x0], this[_0x46d6cd(0x1c8)] = _0x324dc6[_0x46d6cd(0x1cf)]();
        var _0x366f13 = _0x23fedf[_0x46d6cd(0x187)]('tar\x20-xzf\x20' + this['tarball'] + '\x20-C\x20' + this[_0x46d6cd(0x1c8)], { 'silent': !![] });
        expect(_0x366f13[_0x46d6cd(0x196)])[_0x46d6cd(0x1c4)](0x0), this[_0x46d6cd(0x1cb)] = require(_0x49c651[_0x46d6cd(0x1aa)](this[_0x46d6cd(0x1c8)], _0x46d6cd(0x1b5)));
    }), beforeEach(function () {
        var _0xb073ad = _0x44353d;
        jasmine[_0xb073ad(0x1b2)]({
            'toExistInPath': function () {
                return {
                    'compare': function (_0x9c0528, _0x19ca9b) {
                        var _0x587e9d = a137_0x3e64, _0x4ce37a = _0x49c651[_0x587e9d(0x19c)](_0x19ca9b, _0x9c0528);
                        return { 'pass': _0x368879[_0x587e9d(0x1c3)](_0x4ce37a) };
                    }
                };
            }
        });
    }), afterAll(function () {
        _0x368879['unlinkSync'](this['tarball']);
    }), it('has\x20a\x20root\x20path', function () {
        var _0x3055b2 = _0x44353d;
        expect(this[_0x3055b2(0x1cb)]['files'][_0x3055b2(0x1bd)])[_0x3055b2(0x19b)](_0x368879['realpathSync'](_0x49c651[_0x3055b2(0x19c)](this['tmpDir'], _0x3055b2(0x197))));
    }), it(_0x44353d(0x192), function () {
        var _0xbb2e25 = _0x44353d;
        expect(this['packagedCore']['files'][_0xbb2e25(0x198)])['toEqual'](_0x368879[_0xbb2e25(0x1bf)](_0x49c651[_0xbb2e25(0x19c)](this[_0xbb2e25(0x1c8)], _0xbb2e25(0x197))));
    }), it(_0x44353d(0x19f), function () {
        var _0x597d77 = _0x44353d;
        expect(this['packagedCore'][_0x597d77(0x191)]['jsFiles'])[_0x597d77(0x19b)]([
            _0x597d77(0x1cc),
            _0x597d77(0x1b3),
            'json2.js'
        ]);
        var _0x2c08e8 = this['packagedCore'];
        this[_0x597d77(0x1cb)]['files'][_0x597d77(0x1af)][_0x597d77(0x19e)](function (_0x42c39d) {
            var _0x3c624e = _0x597d77;
            expect(_0x42c39d)['toExistInPath'](_0x2c08e8[_0x3c624e(0x191)][_0x3c624e(0x1bd)]);
        });
    }), it('has\x20cssFiles', function () {
        var _0x2a33d9 = _0x44353d;
        expect(this[_0x2a33d9(0x1cb)]['files'][_0x2a33d9(0x1a0)])[_0x2a33d9(0x19b)]([_0x2a33d9(0x1b0)]);
        var _0xe81f63 = this[_0x2a33d9(0x1cb)];
        this[_0x2a33d9(0x1cb)][_0x2a33d9(0x191)][_0x2a33d9(0x1a0)][_0x2a33d9(0x19e)](function (_0x3c073f) {
            var _0x4bb73e = _0x2a33d9;
            expect(_0x3c073f)['toExistInPath'](_0xe81f63[_0x4bb73e(0x191)][_0x4bb73e(0x1bd)]);
        });
    }), it(_0x44353d(0x189), function () {
        var _0x120ebc = _0x44353d;
        expect(this[_0x120ebc(0x1cb)][_0x120ebc(0x191)][_0x120ebc(0x1a3)])['toEqual']([_0x120ebc(0x1b6)]), expect(this[_0x120ebc(0x1cb)][_0x120ebc(0x191)][_0x120ebc(0x190)])[_0x120ebc(0x19b)]([_0x120ebc(0x1a2)]);
        var _0x20b975 = this[_0x120ebc(0x1cb)];
        this['packagedCore'][_0x120ebc(0x191)]['bootFiles'][_0x120ebc(0x19e)](function (_0xc438ef) {
            var _0x21e3a1 = _0x120ebc;
            expect(_0xc438ef)[_0x21e3a1(0x1ad)](_0x20b975['files'][_0x21e3a1(0x198)]);
        });
        var _0x20b975 = this['packagedCore'];
        this['packagedCore'][_0x120ebc(0x191)][_0x120ebc(0x190)][_0x120ebc(0x19e)](function (_0x58091c) {
            var _0x55196e = _0x120ebc;
            expect(_0x58091c)[_0x55196e(0x1ad)](_0x20b975[_0x55196e(0x191)][_0x55196e(0x198)]);
        });
    }), it(_0x44353d(0x1c6), function () {
        var _0x43b330 = _0x44353d;
        expect(this[_0x43b330(0x1cb)][_0x43b330(0x191)][_0x43b330(0x195)])[_0x43b330(0x19b)](_0x368879[_0x43b330(0x1bf)](_0x49c651[_0x43b330(0x19c)](this[_0x43b330(0x1c8)], _0x43b330(0x1be))));
        var _0x1586c4 = _0x368879[_0x43b330(0x18b)](_0x49c651[_0x43b330(0x19c)](this[_0x43b330(0x1c8)], _0x43b330(0x1be)));
        expect(_0x1586c4)[_0x43b330(0x18f)](_0x43b330(0x1c9)), expect(_0x1586c4)['toContain'](_0x43b330(0x18d)), expect(_0x1586c4)[_0x43b330(0x18f)](_0x43b330(0x1ab));
    }), it(_0x44353d(0x1a6), function () {
        var _0x52e2fc = _0x44353d;
        expect(_0x368879[_0x52e2fc(0x1c3)](_0x49c651['resolve'](this['tmpDir'], 'package/.circleci')))[_0x52e2fc(0x1c4)](![]), expect(_0x368879[_0x52e2fc(0x1c3)](_0x49c651[_0x52e2fc(0x19c)](this[_0x52e2fc(0x1c8)], _0x52e2fc(0x1c1))))[_0x52e2fc(0x1c4)](![]);
    }), it(_0x44353d(0x1a1), function () {
        var _0xd9ddfc = _0x44353d, _0x5730b6 = _0x368879[_0xd9ddfc(0x18b)](this['tmpDir']);
        expect(_0x5730b6)[_0xd9ddfc(0x19b)]([_0xd9ddfc(0x18e)]);
    }), it(_0x44353d(0x1ae), function () {
        var _0x500ee3 = _0x44353d, _0x374093 = _0x368879[_0x500ee3(0x18b)](_0x49c651[_0x500ee3(0x19c)](this[_0x500ee3(0x1c8)], _0x500ee3(0x18e)));
        _0x374093[_0x500ee3(0x188)](), expect(_0x374093)['toEqual']([
            _0x500ee3(0x1b8),
            'README.md',
            _0x500ee3(0x1bc),
            _0x500ee3(0x1c0),
            _0x500ee3(0x18a)
        ]);
    }), it(_0x44353d(0x1b4), function () {
        var _0x403984 = _0x44353d, _0xbd72a3 = _0x368879[_0x403984(0x18b)](_0x49c651[_0x403984(0x19c)](this['tmpDir'], _0x403984(0x1be))), _0x445771;
        for (_0x445771 = 0x0; _0x445771 < _0xbd72a3['length']; _0x445771++) {
            expect(_0xbd72a3[_0x445771])[_0x403984(0x19d)](/\.(svg|png)$/);
        }
    }), it(_0x44353d(0x1d0), function () {
        var _0x1b4f98 = _0x44353d, _0x55d493 = [], _0x5d973a;
        function _0x4e203b(_0xdc4103) {
            var _0x1b6789 = a137_0x3e64, _0x49abda = _0x368879['readdirSync'](_0xdc4103, { 'withFileTypes': !![] }), _0x9c6b8;
            for (_0x9c6b8 = 0x0; _0x9c6b8 < _0x49abda[_0x1b6789(0x1c5)]; _0x9c6b8++) {
                dirent = _0x49abda[_0x9c6b8], dirent['isDirectory']() ? _0x4e203b(_0x49c651[_0x1b6789(0x19c)](_0xdc4103, dirent[_0x1b6789(0x1c2)])) : _0x55d493[_0x1b6789(0x1cd)](_0x49c651['resolve'](_0xdc4103, dirent['name']));
            }
        }
        _0x4e203b(_0x49c651[_0x1b4f98(0x19c)](this[_0x1b4f98(0x1c8)], _0x1b4f98(0x1ce)));
        for (_0x5d973a = 0x0; _0x5d973a < _0x55d493[_0x1b4f98(0x1c5)]; _0x5d973a++) {
            expect(_0x55d493[_0x5d973a])[_0x1b4f98(0x19d)](/\.(js|css)$/);
        }
    });
}));