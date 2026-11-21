Name:           netautopsy
Version:        0.1.0
Release:        1%{?dist}
Summary:        Evidence-based network diagnostics for Linux
License:        MIT
URL:            https://github.com/root465-lipcripto/netautopsy
Source0:        %{name}-%{version}.tar.gz
BuildRequires:  cargo
BuildRequires:  gcc
Requires:       iproute
Requires:       iputils
Requires:       glibc-common
Requires:       glibc
Requires:       libgcc

%global debug_package %{nil}
%global _build_id_links none

%description
Collect local network evidence and run bounded connectivity probes on Linux.
Export a JSON capture and inspect it offline.

%prep
%autosetup -p1

%build
cargo build --locked --release

%install
install -Dpm 0755 target/release/netautopsy %{buildroot}%{_bindir}/netautopsy

%files
%license LICENSE THIRD_PARTY_LICENSES
%doc README.md
%{_bindir}/netautopsy
