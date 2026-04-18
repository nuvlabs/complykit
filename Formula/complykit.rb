class Complykit < Formula
  desc "Compliance-as-code CLI for startups — SOC2, HIPAA, CIS scanning"
  homepage "https://github.com/complykit/complykit"
  url "https://github.com/complykit/complykit/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "PLACEHOLDER_SHA256"
  license "Apache-2.0"
  head "https://github.com/complykit/complykit.git", branch: "main"

  bottle do
    sha256 cellar: :any_skip_relocation, arm64_sonoma:  "PLACEHOLDER"
    sha256 cellar: :any_skip_relocation, arm64_ventura: "PLACEHOLDER"
    sha256 cellar: :any_skip_relocation, sonoma:        "PLACEHOLDER"
    sha256 cellar: :any_skip_relocation, ventura:       "PLACEHOLDER"
    sha256 cellar: :any_skip_relocation, x86_64_linux:  "PLACEHOLDER"
  end

  depends_on "go" => :build

  def install
    system "go", "build", *std_go_args(ldflags: "-s -w -X main.version=#{version}"), "."
    bin.install "comply"

    generate_completions_from_executable(bin/"comply", "completion")
  end

  test do
    assert_match "ComplyKit", shell_output("#{bin}/comply --help")
    assert_match "scan", shell_output("#{bin}/comply --help")
  end
end
