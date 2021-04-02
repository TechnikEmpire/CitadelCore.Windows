# CitadelCore.Windows

This is the open source version of our filtering proxy for Windows. It is now in a feature freeze, and will only receive bug fix patches. Development continues privately at Technik Empire.

This is a platform-specific implementation of the abstract [Citadel Core library](https://github.com/TechnikEmpire/CitadelCore) for Windows. This library implements the packet diversion mechanism required by the base Citadel Core library using [WinDivert](https://github.com/basil00/Divert). 

As of version 3.0.x, this library is licensed under the [MPL 2.0](https://www.mozilla.org/en-US/MPL/2.0/).

This project uses the fantastic [WinDivert](https://github.com/basil00/Divert) project via [WinDivertSharp](https://github.com/TechnikEmpire/WinDivertSharp). If this project is useful to you, please consider supporting [WinDivert](https://github.com/basil00/Divert).

[![Build Status](https://travis-ci.org/TechnikEmpire/CitadelCore.Windows.svg?branch=master)](https://travis-ci.org/TechnikEmpire/CitadelCore.Windows)
<a href="https://scan.coverity.com/projects/technikempire-citadelcore-windows">
  <img alt="Coverity Scan Build Status"
       src="https://scan.coverity.com/projects/15515/badge.svg"/>
</a>
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/46d1822c6ec24aa5abfeabe4b2edaa75)](https://www.codacy.com/app/TechnikEmpire/CitadelCore.Windows?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=TechnikEmpire/CitadelCore.Windows&amp;utm_campaign=Badge_Grade)
![NugetLinkBadge](https://img.shields.io/nuget/v/CitadelCore.Windows.svg)
![NugetDownloadsBadge](https://img.shields.io/nuget/dt/CitadelCore.Windows.svg)
