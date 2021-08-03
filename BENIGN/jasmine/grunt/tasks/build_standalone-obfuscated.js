var a5_0x347c = [
    'file',
    'process',
    '316UCjabS',
    'SpecRunner.html',
    '192974IIJmfX',
    '5JgrwJa',
    'grunt/templates/SpecRunner.html.jst',
    'Deletes\x20the\x20tmp\x20spec\x20runner\x20file',
    '1125975Znwctl',
    '10273sFcCAG',
    '75PkqTst',
    'write',
    'delete',
    'template',
    'dist/tmp/',
    '66odbSSV',
    'Builds\x20a\x20standalone\x20distribution',
    'buildStandaloneDist',
    'jasmineVersion',
    'registerTask',
    'build:cleanSpecRunner',
    '4217xuSQVS',
    'build:compileSpecRunner',
    '1584296JccDSX',
    '25043dpCWtH',
    'Processes\x20the\x20spec\x20runner\x20template\x20and\x20writes\x20to\x20a\x20tmp\x20file',
    '1435736frqLhU'
];
var a5_0x1cc669 = a5_0x37fa;
function a5_0x37fa(_0x30ffd3, _0x4cc513) {
    return a5_0x37fa = function (_0x347cdb, _0x37fa7c) {
        _0x347cdb = _0x347cdb - 0xb3;
        var _0x21a106 = a5_0x347c[_0x347cdb];
        return _0x21a106;
    }, a5_0x37fa(_0x30ffd3, _0x4cc513);
}
(function (_0x463302, _0x2faf25) {
    var _0x3478d4 = a5_0x37fa;
    while (!![]) {
        try {
            var _0x5cab8b = parseInt(_0x3478d4(0xc4)) + -parseInt(_0x3478d4(0xc0)) * -parseInt(_0x3478d4(0xc1)) + parseInt(_0x3478d4(0xb6)) * parseInt(_0x3478d4(0xc6)) + -parseInt(_0x3478d4(0xb9)) * parseInt(_0x3478d4(0xcb)) + -parseInt(_0x3478d4(0xbb)) + -parseInt(_0x3478d4(0xb8)) + -parseInt(_0x3478d4(0xbe)) * -parseInt(_0x3478d4(0xc5));
            if (_0x5cab8b === _0x2faf25)
                break;
            else
                _0x463302['push'](_0x463302['shift']());
        } catch (_0x537408) {
            _0x463302['push'](_0x463302['shift']());
        }
    }
}(a5_0x347c, 0xef626));
var grunt = require('grunt');
function standaloneTmpDir(_0x3fbd6a) {
    var _0x31f6a5 = a5_0x37fa;
    return _0x31f6a5(0xca) + _0x3fbd6a;
}
grunt['registerTask'](a5_0x1cc669(0xb7), a5_0x1cc669(0xba), function () {
    var _0x59a49a = a5_0x1cc669, _0x1fae2a = grunt[_0x59a49a(0xc9)][_0x59a49a(0xbd)](grunt[_0x59a49a(0xbc)]['read'](_0x59a49a(0xc2)), { 'data': { 'jasmineVersion': global[_0x59a49a(0xb3)] } });
    grunt[_0x59a49a(0xbc)][_0x59a49a(0xc7)](standaloneTmpDir(_0x59a49a(0xbf)), _0x1fae2a);
}), grunt[a5_0x1cc669(0xb4)]('build:cleanSpecRunner', a5_0x1cc669(0xc3), function () {
    var _0x443abe = a5_0x1cc669;
    grunt['file'][_0x443abe(0xc8)](standaloneTmpDir(''));
}), grunt[a5_0x1cc669(0xb4)](a5_0x1cc669(0xcd), a5_0x1cc669(0xcc), [
    'buildDistribution',
    'build:compileSpecRunner',
    'compress:standalone',
    a5_0x1cc669(0xb5)
]);