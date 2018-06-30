# CitadelCore.Windows
This is a platform-specific implementation of the abstract Citadel [Core library](https://github.com/TechnikEmpire/CitadelCore) for Windows. This library implements the packet diversion mechanism required by the base Citadel Core library using [WinDivert](https://github.com/basil00/Divert). Since we ported [WinDivert.h to be a C# Pinvoke class](https://github.com/TechnikEmpire/CitadelCore.Windows/blob/master/CitadelCore.Windows/Diversion/WinDivert.cs) in this library, and because we bundle WinDivert binaries, this project is under the LGPLv3 license permitted by WinDivert's license.

[![Build Status](https://travis-ci.org/TechnikEmpire/CitadelCore.Windows.svg?branch=master)](https://travis-ci.org/TechnikEmpire/CitadelCore.Windows)
<a href="https://scan.coverity.com/projects/technikempire-citadelcore-windows">
  <img alt="Coverity Scan Build Status"
       src="https://scan.coverity.com/projects/15515/badge.svg"/>
</a>
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/46d1822c6ec24aa5abfeabe4b2edaa75)](https://www.codacy.com/app/TechnikEmpire/CitadelCore.Windows?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=TechnikEmpire/CitadelCore.Windows&amp;utm_campaign=Badge_Grade)
![NugetLinkBadge](https://img.shields.io/nuget/v/CitadelCore.Windows.svg)
![NugetDownloadsBadge](https://img.shields.io/nuget/dt/CitadelCore.Windows.svg)
