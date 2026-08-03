# Homebrew tap formula template for NexProwl.
#
# NOT PUBLISHED. See packaging/README.md before using this file.
#
# Fill the placeholders from the release's checksums.txt, then commit as
# Formula/nexprowl.rb in a repository named Arseno25/homebrew-tap.
class Nexprowl < Formula
  desc "Fast, single-binary reconnaissance engine for DNS, subdomains, ports, HTTP, TLS, vhosts, takeovers, and crawling"
  homepage "https://github.com/Arseno25/nexprowl"
  version "REPLACE_WITH_VERSION"
  license "MIT"

  on_macos do
    on_intel do
      url "https://github.com/Arseno25/nexprowl/releases/download/v#{version}/nexprowl_#{version}_darwin_amd64.tar.gz"
      sha256 "REPLACE_WITH_DARWIN_AMD64_SHA256"
    end
    on_arm do
      url "https://github.com/Arseno25/nexprowl/releases/download/v#{version}/nexprowl_#{version}_darwin_arm64.tar.gz"
      sha256 "REPLACE_WITH_DARWIN_ARM64_SHA256"
    end
  end

  on_linux do
    on_intel do
      url "https://github.com/Arseno25/nexprowl/releases/download/v#{version}/nexprowl_#{version}_linux_amd64.tar.gz"
      sha256 "REPLACE_WITH_LINUX_AMD64_SHA256"
    end
    on_arm do
      url "https://github.com/Arseno25/nexprowl/releases/download/v#{version}/nexprowl_#{version}_linux_arm64.tar.gz"
      sha256 "REPLACE_WITH_LINUX_ARM64_SHA256"
    end
  end

  def install
    bin.install "nexprowl"
  end

  def caveats
    <<~EOS
      NexProwl is for authorized security testing only. Scanning systems you do
      not own or have written permission to test may be illegal.

      The -screenshot flag requires an installed Chrome or Chromium.
    EOS
  end

  test do
    assert_match "NexProwl #{version}", shell_output("#{bin}/nexprowl version")
  end
end
