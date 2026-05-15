class Nerdovault < Formula
  desc "Local Touch ID protected secrets CLI for project environment variables"
  homepage "https://github.com/nonstopdevelopment/nerdovault"
  url "https://github.com/nonstopdevelopment/nerdovault/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "79256a055e4b26cc9c09c3f1c81857365b2d7e98c485069739152255211b5881"
  license "MIT"

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args
    generate_completions_from_executable(bin/"nerdovault", "completions")
  end

  test do
    assert_match "project", shell_output("#{bin}/nerdovault --help")
  end
end
