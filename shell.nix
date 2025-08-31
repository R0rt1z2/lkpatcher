with import <nixpkgs> { };

let
  liblk = python3Packages.buildPythonPackage rec {
    pname = "liblk";
    version = "master";
    src = fetchFromGitHub {
      owner = "R0rt1z2";
      repo = "liblk";
      rev = "master";
      sha256 = "1nlp59iywbnr1s9qsvzp03qs1zlzr22lw34r9cr15v3wagwyclz5";
    };

    pyproject = true;
    build-system = [ python3Packages.setuptools ];
  };

  lkpatcher = python3Packages.buildPythonPackage rec {
    pname = "lkpatcher";
    version = "master";
    src = fetchFromGitHub {
      owner = "R0rt1z2";
      repo = "lkpatcher";
      rev = "master";
      sha256 = "1s77wnm1jc3cgy7xmjicvdc9294qfg0vijfxp8mp3hwgd9cqkjcs";
    };

    pyproject = true;
    build-system = [ python3Packages.setuptools ];

    propagatedBuildInputs = [ liblk ];
  };
in

mkShell {
  name = "lkpatcher";
  buildInputs = [ liblk lkpatcher ];
}
