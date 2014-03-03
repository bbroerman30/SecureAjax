<?php

 // Table of randomly generated RSA keys.
 $RSAKEYTABLE = array( array("02420dd09655c506b6be426172cdd1cf","11baa049bf84dc1213112c2a7cbaa837","1a67adf6d78ff606df7b48a6f3e8ec0f"),
                       array("037bd66e5af125cefa1feb0facff84ad","08ff4ed4f0b7070c52dd4a54697a3985","0d0e864fd9bb408b04dfe95cd9b426c7"),
                       array("060ec96fcf092c4816b1576624fd3eb1","0d971072ba14602f6aea3282356e7151","11b14faaeea9862b4263c99e670811f3"),
                       array("0e01e9901b0b17d6c25f32cd0e69b43f","2ff3e160f8b55f532a912c3e91515d7f","4322c708bca8ab3fa15cdf81c93fd84f"),
                       array("02989043e0d691ada20c9104e24d35fd","2f2b41bc806266f6743957dac1f08ea1","341c11024d94794374e19ff70535dc55"),
                       array("0944908056362a30d5f5b04fb82d037d","272b3a8b01456f88b63d293573fc1fd5","40e663aee2b98481d18c84327c0cb245"),
                       array("20dce8a5702cd74a759cdd9546977209","1d8c13f7d79b75eba99b520e27c9ad79","2b09dc1f799f9965e208253b05f84473"),
                       array("0f39f67f1e5d2873de6dde8e886560e1","0c810abe215c429ec092bf8f891d44d1","109209e55a26f85200173695a2c191af"),
                       array("3285dc4d9baa1901416ac486c5e39cf5","33717120af5f6c6f6c0d61b9ce574505","3a29205b0bcd1173cc4cd04806c85c73"),
                       array("1421954c179a8b6db602b085be6088e5","1f672d40e492560b8f74e346d938563d","24fce5be19d7c042241e8bbac3451d11"),
                       array("0498f76a97b371cffb7c60b91d5e279d","0f05e35adbb806d4238243ea7fcf94dd","1aee2b91752dbe597806e53b4d24d959"),
                       array("17ec6b5fc617ff541617c95f9605eecb","5fb458157bf9a8bed302ccc57116f93b","681ca5b6b69cf141f8c8b78a0efea0f1"),
                       array("a8ab2019018964c468574d4119ea98e3","c12345198d3e4e3d839bfedd66605cab","e73776c414b31312415b84d5fbe3891d"),
                       array("059ac3cb3f0f0b986886bc194f1a85a7","06218fa867a4758619c52b9f8484a4b7","0baccc6eea9817516bec4624a5b2421f"),
                       array("5efc0c3ab2b1a12d3460817b70346e09","5b73c0d952f3213be8ad7d445d369489","8e87adc1dc9406e04d8c19fe8c043c97"),
                       array("536ad57e2321877ee8237b561bbd3fc3","33dc3f662eda802792837e82e4ddb4ab","615e3851cdedaae96aac27c058fb05f1"),
                       array("041eff0e134bf9e3a375b5a11b64850b","176d6fe15dec51dde12799f07c343623","2a35b5f3e537ee228a786afe8a0c3393"),
                       array("06a05bbc1e079372a4a38bb6516e3261","17e28dfc5bbea57e36dcba2a292f2901","26c9d49a4ff552adbbd4ca1fe3f2d925"),
                       array("88abf25553e1876095bd84e4b1c0aa57","785b42be93dffe4ed7c992a93fcca227","9d3de06299df92c59045d9304ecf9137"),
                       array("0451b1e47588d331533581aadb5d6bbf","04d4bc25fdf937783620a6810180a93b","091afda266631b20f2c4f26b54fb7db5"),
                       array("24ab2ec97237f1eeb41eede6e806e60d","347d4471252d7f73f492ba41d4d0ba2d","51ac4ab4db8be569bc26a7b6ac72986f"),
                       array("1adac71147aa0fec0e8045e16bbd15c3","390516e6b14c4b61571f5d26356dd18b","4227c97b83382ff614ccc6028f2e646f"),
                       array("0905f19c8381d728775eb87007d1047d","1106fd5f808cd2c158270e58d6e1c0f5","1bfe575aeba67662fdf333a2b5c87979"),
                       array("0bc27fbd5323d8a4c72fc7a8cbbbca55","10b22989d968d40f83c7d989cc7cbf4d","1e3a55177ffcdd05e31c5013ec78d4e7"),
                       array("08d2e82fbb919432f2779fedddb8debf","0cf4bfe5a24bbae850952523e34348af","153311d2f5153f756f799803446bf96b"),
                       array("0bb823ee279aaf1873b5d4df7ff478a5","170276e81464e289fbef71fa51fc94b5","170ac4fbe5d0abfd4f4255a89a4ea31b"),
                       array("2460a156fda1d6e6e16bfb323f5d16a9","8940b39842892ea97af21b8f1610ca31","8a28d968b9875574d5fbe8cb8547fa1f"),
                       array("5e87f02681365f1e7d683d1099bca957","a298d6124118c304e5fd9ebd464df07f","dd518403ff42b4d02f0a918520d606b3"),
                       array("3ceb01aa1e0d4e1a1a1d9c063e873219","315ab4e3198430a4a8c737f83ce7d9f1","5459e1c9e9b7167f758c2c2de89cb0c3"),
                       array("83386c74f2449999f797cffc00ff6c67","73ba00aa7ec1110aae317bd1bd482747","be45b16f622b20b8460bfae76470a05f"),
                       array("204e445066ea51491d439f146e5722b5","291eeb290b8b7e0463215b3ce9f866dd","41727d9675ba711307530c637dbca44f"),
                       array("0d249c9d6c1cbc26befc3254a3792b13","0fda47e72d17ed787706fb03130c60ab","18074a5c6b3154c2443679ce9db6d3bb"),
                       array("02a75368410e9881e683ef06fd84abfb","02508e896d01faa9c41f02102a5c48e3","049f676b9d3319af65e7b28331da002b"),
                       array("2d496a39bf2672df873cc860278b4a95","319ba1b317a594473bffff36a9854621","4ddf46cabd06081e48e6efdf0b4db42d"),
                       array("04320775dad882a33b015262096266f7","10c7f0474420e8b010f75e9f32be7857","1df0c1be80e6527b523032a7b67257c7"),
                       array("43666a15ecb227b89b439020a508746b","34829fab59c32e2069dafa2c639eefaf","46a7065983a027169dccb1e5eb71e0e1"),
                       array("0b542b8f7393fd57a4490b9aeac5f745","1294b307a95b73d09155bf4c056827ad","1ec8703b9a12f5efa1c20aa590ab54cb"),
                       array("05d1d4160ea99775d236739d03d19b83","0b6b125abb848fa235ffce08314e471b","0ca7efb4bd3045d6315b41fa3b00fd67"),
                       array("3175af8d37bd9434e50a6e03af5c453b","39ddd350aa3cc6df34be8771da06e1f3","40280071994caad5adae730758371b55"),
                       array("0cf4911f7da3656d2f1d0f53b55ce64d","0d0a52d13886d4fd2320301ca983e855","11bca69824eb89cb6717e3d937975c91"),
                       array("05a2672e3d049a6b5448d3d8a783591b","100d31a808190cfed33c214ab152c313","18b4d672335719b8bec05ca5fd63354f"),
                       array("0ca8756e30ad33bbdcbcaf42db31783d","0e4d78fa21c8abf21755594447742a5d","1586ccdafc87d1021a716b933d49cf03"),
                       array("02dfd8624eaecdf3958253632ab0edcd","0463efafa4fd6502bbcf99eea8216aed","0609de649870ec9a8e831834c26e5a2b"),
                       array("1a164b1d8184436d620eb1d1661b9a59","275d13cbcd34cb08de13acd32520bbb1","2ab87277a3ff74d9ef9e5e0c1ff9daaf"),
                       array("317529233651c4b4d6dd8c79e908eee7","944d78979a25ebf103511f79f4e9b197","f2b437fe2ec0a013d9bad56f686c4ae7"),
                       array("04e72826e957f271d4af58de5ef388fd","07927e7e0497b809fee81fffae70e709","0b104e7f1b3927edb8e155591e71dcad"),
                       array("03ddef495a6713efee50ba42d59916ab","0f0a20a70047490a4bed3e121855a403","1ca828e222077c5c84aeec3944d1997d"),
                       array("1776724a4244d4185c235cd6470d0ca9","2f9368bcb75dace28cb592b1f25fbf19","395543951ddc4eb911b88a184b7d3057"),
                       array("7a6cb45bd8efc731a96f14c5b0cbb5fd","5f08835cedf545e348a786fc2b8b1245","7d3e0b06e04881a92d4fd0bc907736f1"),
);

function chooseRandomRSAKey()
{
    global $RSAKEYTABLE;

    list($usec, $sec) = explode(' ', microtime());
    srand( (float)$sec + ((float) $usec * 100000) );
    $idx = rand(0, count($RSAKEYTABLE)-1);

    $rsaKey = array();
    $rsaKey['public'] = $RSAKEYTABLE[$idx][0];
    $rsaKey['private'] = $RSAKEYTABLE[$idx][1];
    $rsaKey['mod'] = $RSAKEYTABLE[$idx][2];
    $rsaKey['size'] = strlen($RSAKEYTABLE[$idx][0]);

    return $rsaKey;
}
?>