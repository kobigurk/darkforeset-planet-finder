extern crate num;
extern crate num_bigint;
extern crate num_traits;

use tiny_keccak::Keccak;

use num_bigint::{BigInt, Sign};
use num_traits::Zero;
pub use crate::num::Num;

const SEED: &str = "mimc";

pub struct Constants {
    r: BigInt,
    n_rounds: i64,
    cts: Vec<BigInt>,
}

pub fn modulus(a: &BigInt, m: &BigInt) -> BigInt {
    ((a % m) + m) % m
}

pub fn generate_constants() -> Constants {
    let r: BigInt = BigInt::parse_bytes(
        b"21888242871839275222246405745257275088548364400416034343698204186575808495617",
        10,
    )
    .unwrap();

    let n_rounds: i64 = 220;
    let cts = get_constants(&r, n_rounds);

    Constants {
        r: r,
        n_rounds: n_rounds,
        cts: cts,
    }
}

pub fn get_constants(r: &BigInt, n_rounds: i64) -> Vec<BigInt> {
    let c_strs = vec![
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0fbe43c36a80e36d7c7c584d4f8f3759fb51f0d66065d8a227b688d12488c5d4",
        "0b1be1e55d1138dcfc4eeee6618b1b7cde5c4a262e83139555673f5751efc1c9",
        "27c0849dba2643077c13eb42ffb97663cdcecd669bf10f756be30bab71b86cf8",
        "2bf76744736132e5c68f7dfdd5b792681d415098554fd8280f00d11b172b80d2",
        "02aef041c0700b1b4b2c4629195a5a3c737b1ea990e32486c9e2d748cec58567",
        "282767ed3103cd92e2b5593b56115d06ae8d9ddc64255baea0764a3f651e9b2f",
        "10f3a13e8bb8523daf4769cff22133d7ad0823f6e220567f516ba73eac4f4c34",
        "0fef545f7ed94f69e3485fb572d1e82497fd1f63a84cd2d007fff998f7e40bdd",
        "15ceee0e1c70f77bd1136f3709d40c4298e75763b8595db0c41daf954c4537ce",
        "0a9baee798a320b0ca5b1cf888386d1dc12c13b38e10225aa4e9f03069a099f5",
        "2670d407ad0b5a999abd17b3f98dbe505989622060911b2bcee42e2d51b32c76",
        "161ed19c62ea260285d1fbc1350909f6008b8c95ef331a4d154f5fae54eb8b16",
        "1a4dc528312f210eb17dfb6851f05fa4cd7e0139852ebbf4ae00590b88c8855a",
        "25147dcc3df52742c7329ca5563c4c4fd696489c63394bc1415ecbfb1226875f",
        "01a811a20cda427c2b6ad3d58164136f874ffb51415beed111a52bf31006016a",
        "0824de9e43d882ee2a068eea1318a0dc3da826e52825768765ae4774621b2a63",
        "10b4f82b62f0fc9a53ffaf9f21359e56712d2045fa64cb8f5fe7beeb230c554f",
        "2d150f8fda7df0d566e8018b6470372e3c161837ca59a53fa1d1d27e4452a0af",
        "281e90a515e6409e9177b4f297f8049ce3d4c3659423c48b3fd64e83596ff101",
        "11dd375328f0481fb8a78d762b28cec882569c0434ee7ce4c949a0c701bf3e7c",
        "17de91f8113f9443a73c8f2f1274fc39021217080b4d476127ca3c7ee1f25c05",
        "0bf2b7e871ca735f716032e68b757c912b2ffe442c58cb03cc30b52b9b24bced",
        "0a3908129452ca7d00584afd40b6a4a71f0e856fff2d71c1efd6f607486195c0",
        "253e5bbfe718ac84611d8e52c9e70573ef235ec1c22724484b087e5c3452aa35",
        "0a380e47fbd10c830a8499cece42bb5e4e95adc619aab8962db105e019265fa7",
        "24e53af71ef06bacb76d3294c11223911e9d177ff09b7009febc484add0beb74",
        "1a43144a8bbba4cf8c6b2785e1a75d29544a1a98b0524c1984afd2b698f2138f",
        "0562fabab7b28094d180eb5917ff5b5a01557afe100bcf971b724d9736d28e4a",
        "042ca040b9419be4c81292c916998dfd67990a13cad5d3c48e9bbdfd6351b065",
        "005449be1e493e0ba054f063a30538d3a5ebe4a0f857ef981f0152c5625dac4e",
        "29bae21b579d080a75c1694da628d0ecfd83efc9c8468704f410300062f64ca9",
        "21950fd25b80edcab7d4c642601992e06654338d0308d8ad1565fbb8b90fce40",
        "2b7c83a5c9472ef3c780b5ec5405db512e0ad3d500edcf7c46693be30e2f183f",
        "0c354c168e5913be8d3cd037600a911d75b5e52529052ec3ca5e053bd401c34d",
        "0929db368ef2af2d29bca38845325b0b7a820a4889e44b5829bbe1ed47fd4d52",
        "16531d424b0cbaf9abbf2d2acde698462ea4555bf32ccf1bbd26697e905066f6",
        "03cd84e6190c3f2636cb944c82c30fb075769b4676b2a0f0cdcb6fb3429d76f1",
        "0def067b7df381dd5650e5ca0cdaec55f8533021da5ed14f954dd2b27023f484",
        "0ee9c4621642a272f710908707557498d25a6fdd51866da5d9f0d205355a6189",
        "18017fcc05938635dc7c6de22f78d6a96daf60c0c33d8e775802be1cdb5a72ee",
        "2cc0823ed1d33029597dc970c98c3b17421478a4e3241cb204fc5feab7a5ee79",
        "1679a0c60f408d8915f0b822c2866d858432f062eea7ce020fcdd4b63303d2f1",
        "0642e8800a48cc04c0168232c6f542396597a67cf395ad622d947e98bb68697a",
        "00569a003785b51067c530fe3a28f55e9363c821d6c35d9dc3c4d322bc0e3df1",
        "2ca7148d40d1dffbc857d2d387c5b12d1ebc6409c37b23473a6a2e0d2bb24fdf",
        "07085e102e77f24e456d886f461173b14e72f7081c41b7e891e69b5975864418",
        "2605b9b909ded1b04971eae979027c4e0de57f3b6a60d5ed58aba619c34749ce",
        "10e54f3fa759dd117dbef6454b0c8c1a76ae867ac758904117f919fec46228cc",
        "2ac5905f9450a21ef6905ed5951a91b3730e3a2e2d62b50bdeb810015d50376b",
        "196dcb542dc5dc51dd05e93f3c0b6de0584eb7295fc645a8b8629512057b9678",
        "06e2724ea4355bea4b417e567bbfc20033307b15f0d2dd4abf6778bbea7270e1",
        "0e786007d0ce7e28a90e31d3263887d40c556dec88fcb8b56bc9e9c05ecc0c29",
        "0b814ed99bd00eca389b0022663dbfddfbfa15e321c19abcf1eaf9556075fb68",
        "04f79535e00c8e918d22cfdc96b4dc310474df0ef8bb5abc21cab45ab25c0930",
        "1a003f39f26d1946291d39f12622b187a5ddc940ee4a37659b646deda0722bf1",
        "0c41a6a8c884710137d7c78fe60cb115b7a195511d19c1a866bf9b7bfdf6501f",
        "1389e0264605b298f1dffb4b71f7b5ece4156caa9e1a4ce51e2f52e887e8ac56",
        "1c6bf6ac0314caead23e357bfcbbaa17d670672ae3a475f80934c716f10aca25",
        "0bdbb96fa5c73c55450cc9348d147f4d3d554dd498d09c3b6d995fb8951a6431",
        "1d199f2e0212faff4d49341b2c16b888af6e152fe52c76cd364850e242b0697b",
        "0206f877af22e702a1d11a12eadd06581ee96969440528d3ec695b008c8c2d1a",
        "2287cef47bc395079ba67071bfc62b6d434bd8b587db1c10c2f8b7dd3296e394",
        "13ceeeb301572b4991076750e11ea7e7fcbfee454d90dc1763989004a1894f93",
        "243cd698bc31534698384234086d0b05373350b0bb0bcaa0880937187135fe62",
        "005f3e9502bcc9cdaff22b01bfbd157c038d0bf9d2f994de082b9d2a78a258b3",
        "12692a7d808f44e31d628dbcfea377eb073fb918d7beb8136ea47f8cf094c88c",
        "260e384b1268e3a347c91d6987fd280fa0a275541a7c5be34bf126af35c962e0",
        "16fb013611a71040326dd1fa7cc948f484617c015bfbe3679574fca48b6dadd8",
        "27519b325c443a8a61972952280f298f56879fa427b5ba7e97357dd6230bf048",
        "248d7432273cc8d37acb20fc8bd1c42729d49de75812ba98cc4d5c1ebdbfe906",
        "296632d868ae6d5178c87f83a805867400246284fa6f02ccc4cbf0d22c457f74",
        "0fc4c0bea813a223fd510c07f7bbe337badd4bcf28649a0d378970c2a15b3aa5",
        "0053f1ea6dd60e7a6db09a00be77549ff3d4ee3737be7fb42052ae1321f667c3",
        "2a0236ac364a48575730567432e8608546e1eb422e19361ad861ef06bbaa4a00",
        "299e29684dbbad05668eff255292aeecd250c636476234334c197271e9725204",
        "1c3c5d45dd862fcbba507c30740cafb0f37e5b8c1dea76b3f46234b165ad40bd",
        "190db6088d1f103103047bf2dc934e1311f68981e5a5eef29b11f43d8aa551b1",
        "153dae43cef763e7a2fc9846f09a2973b0ad9c35894c220699bcc2954501c6bd",
        "135bf03db291930e1a0f35a0959bcf9c1d08b378604edb731c8dcde50090e877",
        "0063a5c4c9c12dcf4bae72c69f3a225664469503d61d9eae5d9553bfb006095b",
        "1af9136a286264f6f230246b925772426d682ba0d75c462a0f18a2ae6dc9d829",
        "180753a64f5d6c5ac2d2b6fdc31e2ff7f0f14e77a1c6e6ff0a9fcc33914f483a",
        "047511ce5f700c7622cffccf387cc2d313f432aa82a642d1b2757ceec423bcf2",
        "303b2e0148b6e2e840210a07aad2a1363e6e0995acddd414ad828d7c2437465a",
        "0ae2c1b55001c365f165f98973a139116caa3230e3f95c417169be16c51ad475",
        "040273e4476ca817284ea880868d3b1ffdae6f8e6bb9cd375d79ef55499554a0",
        "17e650317d66cdc90afb8e5f46c39a7368ebc43964d2696fcc869bc4baa53172",
        "028cf41e1568f34c298a1907c42d3345245414f11243f73c364c6ed1aeaf8c0d",
        "0b1227b61b387d976fbd1def142ccb1f6525447f81dc39c4fa90ad497e32c9f0",
        "058d6ba2805c898fb504a70b4a30b2147f409f0b87ada948c1d44bc4048ff155",
        "00129c7cd00e42ed05a37dbceb80d47b65e1d750ef2148278a54723fdf42c4cc",
        "172e37fd8e22a67b33e39e53e472be036768f44d0db94a2bc6f4f958cb195885",
        "047b173545551de00d61f1da993dcb1d7053d95b9f39091b35d25143e311f5e9",
        "2091e82677269f493582929eda966641bd9f9e9b790c2e0382c081d999f9c32b",
        "2096bacda358c7852feceecda079851c86c891e261057bdd20ae592a2bf63e7c",
        "29894ebd83a0b97b8d77c42299de988878354a8fcebb20257290b0ffd89cdd8a",
        "086903abb30acb73994b6192f8a252cbe45de344dd52a64b4f66c13f652db8a0",
        "24f14d18d66c1856e3f6a8abfd9a0484b0b2f0537f9128f65d5e81c5e1ba8962",
        "1874b5c285e4210f8864c029856dd6023f64334ab15ed2d3eb50466e86a44a07",
        "063d0b01a883ac19b227113a85d5ebadd942e4a944d3a4fcffb2a3c0e1cb0f16",
        "269e6bea132772bc395c64451eb818dba2ebc6aa296ad3ce36e7c8dddbf249ef",
        "03797301a98cdfe52c2e248bde41b2ad09e5dc86ee7b36e650ccf4e25b79f460",
        "163308ae1413439a1708c5fd556bf624cddb3097baefca7d34915ae04e26eb1e",
        "08cd97bf5077b356e26d76194df9ddf9324654de795e692fe72e3e628ebd4cbf",
        "09a6fddec902d117780b231a9e1f5852093bbe5cef4a0cf93dfbef782df536b4",
        "0549b629f1d3860b8ea2a224ed088f0672b79618912f0cae5576471099eaf546",
        "00793e6dfe7f4611ee027f69d4b400af1eb7fb0e3f6266f99fc1999e9c978c62",
        "283857e88bbf48dc9b7028273ed6840491f4514ecbaf948b54d248f228716efa",
        "223da47c2ec498722f26aab8927b70a8bd5f0c08f1d15e4a5bbae244128e69b5",
        "166c6bf34a1e6fe1e1eaaf69d17530d5d6b834c9af51afa281129bb4993d8ba2",
        "18dd55b4a83a53f2ee578eb3e6d26f594824d44670fc3f4de80642344d15c09a",
        "0e88ca3c50f6e50e0b69e7ea68ec50092e8b92b499e29cd91d29b00b5c3604b3",
        "1901d8f4f2c8449128e00663978f2050f2eb1cd6acb60d9d09c57c5d46ee54fe",
        "2e611916dd7984c5c692e9a2cbde6d04c425f7a319a6fd3698e508d1233a7db3",
        "01c0b2cbe4fa9877a3d08eb67c510e8630da0a8beda94a6d9283e6f70d268bc5",
        "0b1d85acd9031a9107350eed946a25734e974799c5ba7cff13b15a5a623a25f0",
        "204497d1d359552905a2fe655f3d6f94926ea92d12cdaa6556ec26362f239f64",
        "1ee4be22419c99e69ebd1c27993f9b1d51b6824b7379ceac5e5ca2cbb2a2a5ec",
        "243f46e353354256ab8fe0ca4e9230dfc330bc163e602dfeaf307c1d1a7264b9",
        "12b77492849bdefb1bbc5c55c3c82d9243f39a6009c361c7745280a45e9ecce7",
        "2f312eef69a33d9fa753c08840275692a03432b3e6da67f9c59b9f9f4971cd56",
        "2eceeb23cdf17babea42cdc72796a98469730a063b793c893a8ca496e0efbbff",
        "17ca868794a5a2b09ff219856b27d11890abf3d59958a90a13e569ff3abd8a5f",
        "0ec3c87f00cf5519cd60e5e894dfc3382e28a73f6a62b41760b937c255df83a6",
        "0b0a5017a4a351d91f366611585b8d160379b669b243e657d8df7776f4a238b5",
        "2899c036db850a580a15f86e9ae418e9cb2ef4f15265d825f09f16870ec8c336",
        "07c085730b2b73e8012a1b69807c18db4b962ce1fee9aee363ec111831f8a7bd",
        "008cc717b97762132791cba6294baf287217cb1f8d3467898de67018cca91f44",
        "164eda75fda2861f9d812f24e37ac938844fbe383c243b32b9f66ae2e76be719",
        "2f15c2779a9570363b897cdeb055ddfe284f6571fbe189a414b33f5bf31afcbc",
        "24fc7ca023cb6e65f3e6d9c4c0fa92776956fbd1f1abe119b1b4b9dfb0334b4b",
        "09e0573e21c5e8107335eaed49658e7e063a5ff33e167aa34ee9e383a3ef598d",
        "132f51760e46faa17b7bab733908e244952d68c19dc6b20f0d95d431b1c59bf0",
        "0242f85dca68c13f3189dd0096c9ab2b0cf01e4754a9280cfcc411b7fd55d771",
        "042cae37aec897c9a57635298566baf59edc50fcc7c21db9d049071b0a344b84",
        "095526cb4b2cc423e912e906df854e76a5bc30530927c87732d34a4a00881870",
        "063f1db81f5540a85b592e5e4567fcb0a6f615803de26f24012a32a2b18a70a7",
        "2a626b47b2d26d2cda681fffe5fa089209cdcd79985d2965c809aa073528a025",
        "17d5b87c3657df3c89d69eba72fc4c3480a0f4be451896520807d892481628fd",
        "284e583469ea05fdf11f2ae897a70e557c8703ae3c18726e78a95023d5b98d23",
        "255daa128f75da34d00d137a0eee7e06ead6bf071c830e3c5c78b92a2d57def5",
        "0052e9a9b5f419b14f3125f903a33bdd519ab8ed06c3143b9ca13ef1d11e0c2d",
        "0582d5b3b958cd5eb1a90e55b3ef8eb245d8ecdba20dba510110ac923f3a989c",
        "04df8c0defdc02280cf831b967866c926165551a664cba547c677a37951c3660",
        "2382d616e8c47fdd4fbbb676a088dc9d20469c41cff2f587313498ec5d0b1b02",
        "0d086948c84c5518221f92df23f89c4a360e89aa08bd10658158d2dd68060c91",
        "0af02d0e1317d88c923e7a30aee3f519da6d9660607ea33def8b7d84465093fe",
        "23b0c3ba6f80cf25f3073e49cad576a6c8f50fdd3368c6636ff329e0837bd972",
        "00e115c4a98efae6a3a5ecc873b0cef63ccd5b515710a3ab03ec52218f784dc9",
        "18ec1888a2f457d4a6e26f7dbc0dcfafb4a91b54c37c7e72e9ea61d577a202a7",
        "226a91a571ed1b2f9061e56f764fdfe8a4ade867a8a359ac46308e76104c62f6",
        "1f71e007903cbfe8c8898fe2e8532eb94b29ce61e49759565cb845d7ce62aa15",
        "24e65c718938c2b937378e7435332174329730bde85a4185e37875824eb49859",
        "081b774b0a70dc72788a142dca2be4a1c31de964fa1a5df0b5b28901684a8eb8",
        "2f0c13445d90cb0ebc547403eb00095d6b790cbd80204cf69d737f8a33d1ffa6",
        "23248698612cd8e83234fcf5db9b6b225f4b0ba78d72ef13ea1edff5f0fb0298",
        "1118c071b4fb39eb0db94f9017b1baf96d7e9a4e8f40edd46ac68397510cf0d0",
        "00f7f822f933820f4731c9ff31b4dc51256770608cbc2fabb574b1b945c82ef8",
        "01cd399556445e3d7b201d6c5e56a5794e60be2cfd9a4643e7ead79bb4f60f79",
        "1b58716ce9cada90d6a0d672ff670579d37fc4b39d27bb8d9c92c7e3b3a8312c",
        "058402b966fb4ab2cd74280ef64d4956f68fbcfb11b6815af104fb76b8171811",
        "2398eafda87885d51410d7d592c0ca308518a760f0c7eb3e5025b7976986b2ad",
        "0dd2dfe8f3aa9e4d3ceb2b16f4a19a95b71b92da9cd9c778622bae6482c9d728",
        "1482ac3e7e4f321627850d95a13942aea6d2923402b913046856ff7e8aaf9aff",
        "17332b4c7aac2a07ccfe954de7ad22ccf6fcb4c5fa15c130ed22a40ae9398f47",
        "132ccb7a7c7903f9f0a001d96f8410c6b81382764b7d9f280b7b993b7fdd857f",
        "1521dbdf2f88fd7c10c0b3200849caca5b4aae7dbb2b7bb8d08bc01609b7b082",
        "2a0892d6b1ae3cabd6a34b075099d59a3bff87e01694c5895bad732373526d32",
        "15a16435a2300b27a337561401f06682ba85019aa0af61b264a1177d38b5c13c",
        "22616f306e76352293a22ab6ee15509d9b108d4136b32fa7f9ed259793f392a1",
        "2132d93f742f2ac654908e42903beaf9d0d32dc23b5efd0fc680a6e8dae1851d",
        "0e6264ac0dc6688a1fd7be3423b7267356bbb28b6a50a1149a901a2942ae638e",
        "17dead3bfa1968c744118023dead77cdbee22c5b7c2414f5a6bdf82fd94cf3ad",
        "2bef0f8b22a1cfb90100f4a552a9d02b772130123de8144a00c4d57497e1d7f4",
        "2e249d189c5ab035f344531c0e4b9b1ba214be09a0f861a1fbf521384d152a0e",
        "0b468ebcf7fc9de942e6d629d607e97ee1dca77426ee678a444f7a255d6b4dfd",
        "13681ba8a95a21e65720051ff644e617f6e6d285e65b0dcc2ad0cba02338d9a6",
        "0bb7f176c4c62cab92855f63a0c9e7374f1e7e89227dc2703a672b43491ad644",
        "02aa427b8648ae82ff39c8f47497e596c2a49bc16a845262a409a76836768a78",
        "0c40f19ecd5513a5ea3acef661b2fa797737dff7847fee1b86522277eb3ebcc3",
        "1861ae1e114291d107945129389362b0923d2bd63b8db9a51bef3a9004fe6295",
        "2a6ba2a368b91dd670ab0224bc29c24c852397436035daef124f258f08cdebf1",
        "25b068c942724c424ed5851c9575c22752c9bd25f91ebfa589de3d88ee7627f9",
        "2c0767c7996f9a36404cca45f1823a62707d38f7db68199c4bb32b410e01e1a6",
        "067a20b1df30438e616c4a461dce9e6225b52d0cc49daf3b9e54de8f0f518540",
        "215deaf3c2fe9f8a3785e8bc5f7872525d2fd0f0eee1d69316bd8797bb4b70c9",
        "2fb50b2d3af74321e7ddbcf3f573e116586e4cb458dd9be75d9242f27d0fcc74",
        "02c871f0ddf5dfc9e98ce87f78923799449f3b2fe580816aa16ea2502f1bad5f",
        "0871d0eb7536b5ad54e6a9588d9e9770544eb394e71fed7dae196604956280a3",
        "13218626665c420d3aa2b0fa49224a3dce8e08b8b56f8851bd9cb5e25cb3042d",
        "0e9fc2cb907861c7dc61b6c1207b73b3a6d5ace02773f6b0b1bfcfb91873e30e",
        "2a79e5febcf2f8b42ebdffbb42831bea32170ebe2a12121ad4c604b0d22d1c46",
        "2943a0e1e2336d7694fc2df0981487584fa76bbc4feb2a7bf952f59cd5f56ac9",
        "196bc98252f63169ed79073ee091a0e8ed0b5af51017da143940c00bdb863709",
        "17e885a4e49713520e743bca0d6ab7a40f1cfcf0f8fc51afc13aa6aaa8fad6be",
        "26d61bd45f606ca6514b9b293d0ad15655ebe762faed8da11947aa319dc56d43",
        "1efcda9d986cddcf431af4d59c6a7709d650885b7886cba70f0e7cd92b331cdc",
        "123925acd4f1aa1e2a22c32cce354515ca98bde87953b3f3ac6240eb7f60418e",
        "14704dd362d250edaa89359aa8cda1a725de051592e76a5ccddf83ce44c7e41c",
        "1b0273b47db1989e107d5ac9e86d5109438713731fcb8b97696ecb44448dd0a4",
        "17a993a6af068d72bc36f0e814d29fef3f97d7a72aa963889b16a8457409861a",
        "0e535cb0c3f1cdb026576975dc6d29e64093f1e1d5548d90a2787c69fe5a07b3",
        "216c3a201f899c065bce489a4603ec90f57e6d5a5642d6b56d63c0ab3c072b19",
        "0f208cbc3b076c66eb9f87575ad4771877ae410473d21ee109799d04d97bc47c",
        "1c2685c8bb95d9cbd97a5d24ef18089d6064024b701e1c8dedd057a6df967877",
        "0f55ca8ae78360fa3d9b15388528a67eccf126335f9ca6b3eec47209f9fa5957",
        "263e1195090d00be1d8fb37de17ccf3b66d180645efa0d831865cfaa8797769e",
        "24cacf436717ac539e5b7bf56f5ebb01e32bed600dbecd166b14a862aa85029b",
        "105c861f78d37579808457eef387b09fa125918e0d2011e00a878d489b97a2a9",
        "050696b356b09defbc3b0a5d653f22c73a0c5e18b104bf47396c58fb9f89e620",
        "2185b14275ecd4c36288d9d5c844f4dfcc3c61dda109bb64c5c4f1a4ae37b998",
        "0c715b745408b0ba9c797b8199d412f71063e4409b82cda606100c8992372262",
        "23900264b13be89a7a24fb592301daae20bf031546b26237e35ce6edef6cc83c",
        "1f7476211105b3039cef009c51155ae93526c53a74973ecfce40754b3df10521",
        "284aad6697126c6afc69b61cec7f8e86447ac4afb1543014d23b3f3151a5a6e2",
        "009b9d0a9720fffc5b3650a1c0b4debbda89ddb79af5958638cb3d9f02a5a493",
        "186e8b3288ff778ee79bc5445ab38f3cc2af91862231912ca9c22f22b2b07489",
        "04af9e46dbc42b94137981fece56e9775d00fc101129f08fd6b781f439c20c0b",
        "0000000000000000000000000000000000000000000000000000000000000000",
    ];

    let mut cts: Vec<BigInt> = c_strs.into_iter().map(|s| BigInt::from_str_radix(&s, 16).unwrap()).collect::<Vec<_>>();
    cts
}

pub fn mimc7_hash_generic(r: &BigInt, left: &BigInt, right: &BigInt, n_rounds: i64) -> (BigInt, BigInt) {
    let cts = get_constants(r, n_rounds);
    let mut h: BigInt = Zero::zero();
    let mut xl = left.clone();
    let mut xr = right.clone();
    for i in 0..n_rounds as usize {
        println!("round {}, ct: {}", i, &cts[i]);
        let mut t: BigInt;
        t = xl.clone() + &cts[i];
        t = modulus(&t, &r);
        let xr_tmp = xr.clone();
        let t2 = &t * &t;
        let t4 = &t2 * &t2;
        h = t4 * t;
        h = modulus(&h, &r);
        if i < n_rounds as usize - 1 {
            xr = xl.clone();
            xl = xr_tmp + &h;
        } else {
            xr = xr_tmp + &h;

        }
    }
    return (modulus(&xl, &r), modulus(&xr, &r));
}

pub fn hash_generic(arr: Vec<BigInt>, r: BigInt, n_rounds: i64) -> BigInt {
    let mut left = BigInt::zero();
    let mut right = BigInt::zero();
    for i in 0..arr.len() {
        left += &arr[i];
        let (left1, right1) = mimc7_hash_generic(&r, &left, &right, n_rounds);
        left = left1;
        right = right1;
    }
    left
}

pub fn check_bigint_in_field(a: &BigInt, q: &BigInt) -> bool {
    if a >= q {
        return false;
    }
    true
}

pub fn check_bigint_array_in_field(arr: &Vec<BigInt>, q: &BigInt) -> bool {
    for a in arr {
        if !check_bigint_in_field(a, &q) {
            return false;
        }
    }
    true
}

pub struct Mimc7 {
    constants: Constants,
}

impl Mimc7 {
    pub fn new() -> Mimc7 {
        Mimc7 {
            constants: generate_constants(),
        }
    }

    pub fn hash(&self, arr: Vec<BigInt>) -> Result<BigInt, String> {
        // check if arr elements are inside the Finite Field over R
        if !check_bigint_array_in_field(&arr, &self.constants.r) {
            return Err("elements not inside the finite field over R".to_string());
        }

        let mut left = BigInt::zero();
        let mut right = BigInt::zero();
        for i in 0..arr.len() {
            left += &arr[i];
            let (left1, right1) = self.mimc7_hash(&left, &right);
            left = left1;
            right = right1;
        }
        Ok(modulus(&left, &self.constants.r))
    }

    pub fn mimc7_hash(&self, left: &BigInt, right: &BigInt) -> (BigInt, BigInt) {
        let mut h: BigInt = Zero::zero();
        let mut xl = left.clone();
        let mut xr = right.clone();
        let n_rounds = self.constants.n_rounds;
        let r = self.constants.r.clone();
        for i in 0..n_rounds as usize {
            let mut t: BigInt;
            t = xl.clone() + &self.constants.cts[i];
            t = modulus(&t, &r);
            let xr_tmp = xr.clone();
            let t2 = &t * &t;
            let t4 = &t2 * &t2;
            h = t4 * t;
            h = modulus(&h, &r);
            if i < n_rounds as usize - 1 {
                xr = xl.clone();
                xl = xr_tmp + &h;
            } else {
                xr = xr_tmp + &h;

            }
        }
        return (modulus(&xl, &self.constants.r), modulus(&xr, &self.constants.r));
    }

    pub fn hash_bytes(&self, b: Vec<u8>) -> Result<BigInt, String> {
        let n = 31;
        let mut ints: Vec<BigInt> = Vec::new();
        for i in 0..b.len() / n {
            let v: BigInt = BigInt::from_bytes_le(Sign::Plus, &b[n * i..n * (i + 1)]);
            ints.push(v);
        }
        if b.len() % n != 0 {
            let v: BigInt = BigInt::from_bytes_le(Sign::Plus, &b[(b.len() / n) * n..]);
            ints.push(v);
        }
        self.hash(ints)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustc_hex::ToHex;

    #[test]
    fn test_sha3() {
        let mut keccak = Keccak::new_keccak256();
        let mut res = [0u8; 32];
        keccak.update(SEED.as_bytes());
        keccak.finalize(&mut res);
        assert_eq!(
            res.to_hex(),
            "b6e489e6b37224a50bebfddbe7d89fa8fdcaa84304a70bd13f79b5d9f7951e9e"
        );

        let mut keccak = Keccak::new_keccak256();
        let mut res = [0u8; 32];
        keccak.update(SEED.as_bytes());
        keccak.finalize(&mut res);
        let c = BigInt::from_bytes_be(Sign::Plus, &res);
        assert_eq!(
            c.to_string(),
            "82724731331859054037315113496710413141112897654334566532528783843265082629790"
        );
    }
    #[test]
    fn test_generate_constants() {
        let constants = generate_constants();
        assert_eq!(
            "20888961410941983456478427210666206549300505294776164667214940546594746570981",
            constants.cts[1].to_string()
        );
    }

    #[test]
    fn test_mimc7_generic() {
        let b1: BigInt = BigInt::parse_bytes(b"1", 10).unwrap();
        let b2: BigInt = BigInt::parse_bytes(b"2", 10).unwrap();
        let constants = generate_constants();
        let h1 = mimc7_hash_generic(&constants.r, &b1, &b2, 91);
        assert_eq!(
            h1.to_string(),
            "10594780656576967754230020536574539122676596303354946869887184401991294982664"
        );
    }

    #[test]
    fn test_check_bigint_in_field() {
        let r_0: BigInt = BigInt::parse_bytes(
            b"21888242871839275222246405745257275088548364400416034343698204186575808495617",
            10,
        )
        .unwrap();

        let mut big_arr0: Vec<BigInt> = Vec::new();
        big_arr0.push(r_0.clone());
        let mimc7 = Mimc7::new();
        let h0 = mimc7.hash(big_arr0);
        assert_eq!(h0.is_err(), true);

        let r_1: BigInt = BigInt::parse_bytes(
            b"21888242871839275222246405745257275088548364400416034343698204186575808495616",
            10,
        )
        .unwrap();

        let mut big_arr1: Vec<BigInt> = Vec::new();
        big_arr1.push(r_1.clone());
        let mimc7 = Mimc7::new();
        let h1 = mimc7.hash(big_arr1);
        assert_eq!(h1.is_err(), false);
        assert_eq!(
            h1.unwrap().to_string(),
            "4664475646327377862961796881776103845487084034023211145221745907673012891406"
        );
    }

    #[test]
    fn test_mimc7() {
        let b12: BigInt = BigInt::parse_bytes(b"12", 10).unwrap();
        let b45: BigInt = BigInt::parse_bytes(b"45", 10).unwrap();
        let b78: BigInt = BigInt::parse_bytes(b"78", 10).unwrap();
        let b41: BigInt = BigInt::parse_bytes(b"41", 10).unwrap();

        let mut big_arr1: Vec<BigInt> = Vec::new();
        big_arr1.push(b12.clone());
        let mimc7 = Mimc7::new();
        let h1 = mimc7.hash(big_arr1).unwrap();
        let (_, h1_bytes) = h1.to_bytes_be();
        assert_eq!(
            h1_bytes.to_hex(),
            "237c92644dbddb86d8a259e0e923aaab65a93f1ec5758b8799988894ac0958fd"
        );

        let mh2 = mimc7.mimc7_hash(&b12, &b45);
        let (_, mh2_bytes) = mh2.to_bytes_be();
        assert_eq!(
            mh2_bytes.to_hex(),
            "2ba7ebad3c6b6f5a20bdecba2333c63173ca1a5f2f49d958081d9fa7179c44e4"
        );

        let mut big_arr2: Vec<BigInt> = Vec::new();
        big_arr2.push(b78.clone());
        big_arr2.push(b41.clone());
        let h2 = mimc7.hash(big_arr2).unwrap();
        let (_, h2_bytes) = h2.to_bytes_be();
        assert_eq!(
            h2_bytes.to_hex(),
            "067f3202335ea256ae6e6aadcd2d5f7f4b06a00b2d1e0de903980d5ab552dc70"
        );

        let mut big_arr2: Vec<BigInt> = Vec::new();
        big_arr2.push(b12.clone());
        big_arr2.push(b45.clone());
        let h1 = mimc7.hash(big_arr2).unwrap();
        let (_, h1_bytes) = h1.to_bytes_be();
        assert_eq!(
            h1_bytes.to_hex(),
            "15ff7fe9793346a17c3150804bcb36d161c8662b110c50f55ccb7113948d8879"
        );

        let mut big_arr1: Vec<BigInt> = Vec::new();
        big_arr1.push(b12.clone());
        big_arr1.push(b45.clone());
        big_arr1.push(b78.clone());
        big_arr1.push(b41.clone());
        let mimc7 = Mimc7::new();
        let h1 = mimc7.hash(big_arr1).unwrap();
        let (_, h1_bytes) = h1.to_bytes_be();
        assert_eq!(
            h1_bytes.to_hex(),
            "284bc1f34f335933a23a433b6ff3ee179d682cd5e5e2fcdd2d964afa85104beb"
        );
    }
    #[test]
    fn test_hash_bytes() {
        let msg = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";
        let mimc7 = Mimc7::new();
        let h = mimc7.hash_bytes(msg.as_bytes().to_vec()).unwrap();
        assert_eq!(
            h.to_string(),
            "16855787120419064316734350414336285711017110414939748784029922801367685456065"
        );
    }
}
