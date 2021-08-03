var a1_0x2651 = [
    'spec',
    '*.js',
    'exports',
    '11753kQlQqm',
    'dist/',
    'dist/jasmine-standalone-',
    'jasmine-html.js',
    'images',
    'jasmine_favicon.png',
    '293boTSzH',
    '547484ScyLJW',
    'jasmine.js',
    '4212fwnpSm',
    'example/src/',
    'boot',
    '.zip',
    '27103ciNhaR',
    '10ZxlDUg',
    '744051iZopzS',
    '8ZlaYzb',
    'lib/jasmine-',
    '853547ZGhzgj',
    'jasmine.css',
    'src',
    'tmp',
    'boot.js',
    'lib/jasmine-core/',
    '586327aFxLyK',
    'jasmineVersion',
    'SpecRunner.html'
];
var a1_0x1cc84f = a1_0x482f;
(function (_0xd3a542, _0x54c5e7) {
    var _0x31cb5e = a1_0x482f;
    while (!![]) {
        try {
            var _0x5eda79 = parseInt(_0x31cb5e(0x18a)) + parseInt(_0x31cb5e(0x172)) + parseInt(_0x31cb5e(0x187)) + parseInt(_0x31cb5e(0x188)) * parseInt(_0x31cb5e(0x185)) + parseInt(_0x31cb5e(0x178)) * -parseInt(_0x31cb5e(0x186)) + -parseInt(_0x31cb5e(0x17f)) + parseInt(_0x31cb5e(0x17e)) * -parseInt(_0x31cb5e(0x181));
            if (_0x5eda79 === _0x54c5e7)
                break;
            else
                _0xd3a542['push'](_0xd3a542['shift']());
        } catch (_0xe34caa) {
            _0xd3a542['push'](_0xd3a542['shift']());
        }
    }
}(a1_0x2651, 0x7a773));
var standaloneLibDir = a1_0x1cc84f(0x189) + jasmineVersion;
function a1_0x482f(_0x315ce9, _0x3e145d) {
    return a1_0x482f = function (_0x26515a, _0x482f) {
        _0x26515a = _0x26515a - 0x16d;
        var _0x29eb2b = a1_0x2651[_0x26515a];
        return _0x29eb2b;
    }, a1_0x482f(_0x315ce9, _0x3e145d);
}
function root(_0x212fba) {
    return './' + _0x212fba;
}
function libJasmineCore(_0x598f52) {
    var _0x5d4218 = a1_0x1cc84f;
    return root(_0x5d4218(0x171) + _0x598f52);
}
function dist(_0x3b8f7d) {
    var _0x1c16e6 = a1_0x1cc84f;
    return root(_0x1c16e6(0x179) + _0x3b8f7d);
}
module[a1_0x1cc84f(0x177)] = {
    'standalone': {
        'options': { 'archive': root(a1_0x1cc84f(0x17a) + global[a1_0x1cc84f(0x173)] + a1_0x1cc84f(0x184)) },
        'files': [
            { 'src': [root('MIT.LICENSE')] },
            {
                'src': [a1_0x1cc84f(0x17d)],
                'dest': standaloneLibDir,
                'expand': !![],
                'cwd': root(a1_0x1cc84f(0x17c))
            },
            {
                'src': [
                    a1_0x1cc84f(0x180),
                    a1_0x1cc84f(0x17b),
                    a1_0x1cc84f(0x16d)
                ],
                'dest': standaloneLibDir,
                'expand': !![],
                'cwd': libJasmineCore('')
            },
            {
                'src': [a1_0x1cc84f(0x170)],
                'dest': standaloneLibDir,
                'expand': !![],
                'cwd': libJasmineCore(a1_0x1cc84f(0x183))
            },
            {
                'src': [a1_0x1cc84f(0x174)],
                'dest': root(''),
                'expand': !![],
                'cwd': dist(a1_0x1cc84f(0x16f))
            },
            {
                'src': [a1_0x1cc84f(0x176)],
                'dest': a1_0x1cc84f(0x16e),
                'expand': !![],
                'cwd': libJasmineCore(a1_0x1cc84f(0x182))
            },
            {
                'src': [a1_0x1cc84f(0x176)],
                'dest': a1_0x1cc84f(0x175),
                'expand': !![],
                'cwd': libJasmineCore('example/spec/')
            }
        ]
    }
};