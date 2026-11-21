1.
For example, some programs
adopt a best effort approach and focus on gathering as much information as possible from the PE headers. For this reason, they
might not abort the entire process if a structural requirement is not
met, instead preferring to continue the process by focusing only
on those parts of the headers that respect the PE structure. Other
software may implement instead a more rigid structural validation,
thus rejecting the files in which a structural check fails. Even within
the same piece of software some structural checks can be enforced
more strictly than others. This is because not all PE headers play
the same role in all the software implementations of the format:
Some may be essential, while others may be used only for optional
features.

А не надо ли и в моем парсере сделать градацию строгости проверок, или это все-таки out of scope?

2.
Software in this class performs both structural and
compliance checks on the information gathered from the PE headers
of the executable. These constraints are meant to ensure that the
executable provides the data needed for their format-specific signatures. However, they may perform very little memory mapping
operations, usually only to enable signatures to convert RVAs to offsets into the original executable file (e.g., the rva_to_offset function
in yara [43]).

На заметку просто


3.
https://github.com/eurecom-s3/loaders_modeling

Это можно использовать для генерации сложных PE-файлов для теста моего парсера

В разделе «Тестирование и валидация» можно будет указать, что проверял устойчивость своего парсера не только на статическом корпусе Corkami, но и на синтетических дифференциальных тест-кейсах, сгенерированных через SMT-солвер фреймворка EURECOM (loaders_modeling).

4.
We modified the headers of real PE files to deceive ClamAV into not considering them as fully valid PE executables and
bypassing signatures relying on specifics of the PE format. For
instance, by simply adding empty sections at the end of the section table and updating the NumberOfSections field accordingly, the
malware would still be valid for the Windows loader, but ClamAV
would have issues using some PE-specific signatures.

На заметку

