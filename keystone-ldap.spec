%global with_doc 0

%if ! (0%{?fedora} > 12 || 0%{?rhel} > 5)
%{!?python_sitelib: %global python_sitelib %(%{__python} -c "from distutils.sysconfig import get_python_lib; print(get_python_lib())")}
%endif


Name:             keystone-ldap
Version:          1.0
Release:          0
Summary:          LDAP integration for keystone
License:          Apache 2.0
Vendor:           Grid Dynamics International, Inc.
URL:              http://www.griddynamics.com/openstack
Group:            Development/Languages/Python

Source0:          %{name}-%{version}.tar.gz
BuildRoot:        %{_tmppath}/%{name}-%{version}-build
BuildRequires:    python-devel
BuildRequires:    python-setuptools
BuildArch:        noarch
Requires:         python-keystone
Requires:         python-ldap


%description


%prep
%setup -q -n %{name}-%{version}


%build
%{__python} setup.py build


%install
%__rm -rf %{buildroot}

%{__python} setup.py install -O1 --skip-build --prefix=%{_prefix} --root=%{buildroot}

mkdir -p %{buildroot}/usr/sbin
install -m755 keystone-ldap-configure %{buildroot}/usr/sbin/


%clean
%__rm -rf %{buildroot}


%files
%defattr(-,root,root,-)
%doc README* COPYING
%{python_sitelib}/*
/usr/sbin/*

%changelog
