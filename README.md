# PE-Miner
برنامج فكرته الاساسية البحث عن Code Cave في داخل ملفات ال PE / EXE
\
أيضا يملك الخيار للبحث و حقن shellcode بداخل ال cave الذي يجدة!

# صور 
![Photo](https://i.imgur.com/aC9KFwo.png)
\
الواجهة الرئيسية للبرنامج

![Gif](https://i.imgur.com/8HACqc2.gif)
\
مقطع لعملية حقن برنامج ديسكورد

![Photo](https://i.imgur.com/jPzQ4dC.png)
\
اسم البرنامج بعد حقنه

![Photo](https://i.imgur.com/73cugNi.png)
\
البرنامج المحقون بعد تشغيله

# مكتبة PE
أهم ما يحتويه هذا المشروع هم ملفين  \
1 - PE.c\
2 - PE.h\
هما عبارة عن مكتبة مبسطة قمت أنا ببنائها لتسهل التعامل مع ملفات ال EXE / PE 

## الوظائف بداخل مكتبة PE

هذه جميع الوظائف بداخل مكتبة PE
------------------------------------

فنكشن
`PE ExeHeaders(char* path);`
\
يقوم بإستخراج ترويسات ملف ال Exe الممر له مساره ويعيدها في هيكل بيانات PE\
يمكن الحصول على معلومات الترويسات من هيكل البيانات المرجع بهذا الشكل\
**pe.OPTIONAL_HEADER->ImageBase**
\
(يمكنك الاطلاع على جميع البيانات التي تسجل بداخل هيكل PE في فقرة "هياكل البيانات بداخل مكتبة PE")

------------------------------------

فنكشن
`BOOL IsASLR(PE* pe);`
\
تقوم هذه الوظيفة بإخبارك هل ال exe الذي بداخل هيكل ال pe يستعمل الAddress space layout randomization
\
ترجع قيمة FALSE or TRUE
\
تمرر لها مؤشر ال pe الذي حصلت عليه من فنكشن ExeHeaders

------------------------------------

فنكشن
`BOOL EnableASLR(PE* pe, BOOL enable);`
\
تستطيع من خلال هذه الوظيفة تعطيل او تفعيل ال Address space layout randomization
\
في داخل ال Exe عن طريق تمرير مؤشر لل pe وايضا تمرر قمية FALSE للتعطيل TRUE للتفعيل
\
*تنبية التغييرات تحدث في الذاكرة فقط لايتم التعديل على الملف الاساسي*

------------------------------------

فنكشن
`CAVE FindCave(PE*pe,int minsize);`\
تقوم هذه الوظيفة بالبحث عن ما إذا كان يحتوي ال Exe على كهف\
تمرر لها مؤشر لهيكل ال pe و أقل حجم للكهف
ترجع هذه الوظيفة هيكل بيانات CAVE يحوي بداخلة على اسم القسم الذي يوجد به الCAVE\
وحجم ال CAVE عنوانه ومعلومات اخرى (يمكنك الاطلاع عليها في فقرة "هياكل البيانات بداخل مكتبة PE")

------------------------------------

فنكشن
`void WriteToSection( PE*pe, DWORD offset, BYTE*shell,int shellsize);`
\
هذه الوظيقة تعمل على كتابة shell او ماترغب في قسم معين انت تحددة
\
تمرر لها مؤشر لهيكل الpe وعنوان القسم و الshell الذي ترغب بكتابته وطولة
\
لاترجع هذه الوظيفة أي شيء

------------------------------------

فنكشن
`BOOL ChangeSectionCharacteristics(char*section_name, DWORD NewCharacteristics ,PE*pe);`
\
تقوم هذه الوظيفة بتغيير صلاحيات القسم\
تمرر لها أسم القسم الذي ترغب في تغيير صلاحياته وتمرر لها الصلاحيات الجديدة ومؤشر لهيكل ال pe

------------------------------------

فنكشن
`BOOL WriteExe(PE*pe);`
\
هذه الوظيفة تقوم بكتابة ال Exe بناء على هيكل بيانات ال pe\
تستطيع تحديد مسار ال Exe الجديد عن طريق\
pe.PATH = "C:/";\
اذا لم تحدد شيئا سيتم الكتابة على الملف الاساسي الذي تم تمريره لفنكشن ExeHeaders

------------------------------------



## هياكل البيانات بداخل مكتبة PE
```
typedef struct pe {
	CHAR* PATH;  // المسار للملف الاساسي
	BYTE* RawBinaryFile; // هنا يتم تخزين ال Binary الخاص بال Exe أحرص على عمل له free قبل الخروج من برنامجك!!! 
	DWORD PEsize; // هنا يتم تخزين حجم ال Binary / Exe
	BOOL x64; // هل هو 64 bit? TRUE او FALSE
	PIMAGE_FILE_HEADER FILE_HEADER;
	PIMAGE_DOS_HEADER DOS_HEADER;
	PIMAGE_OPTIONAL_HEADER OPTIONAL_HEADER;
	PIMAGE_SECTION_HEADER SECTION_HEADER;
	PIMAGE_NT_HEADERS NT_HEADERS;
}PE;
بيانات هذا الهيكل تتسجل عن طريق فنكشن ExeHeaders

typedef struct cave{
	DWORD Postion; // هذا المتغير يدل على موقع ال Cave بعد كم خطوة من ال VirtualAddress و PointerToRawData
	DWORD VirtualAddress;
	DWORD PointerToRawData;
	DWORD ImageBase;
	size_t Size; // حجم ال Cave
	DWORD Characteristics; 
	int MinSize; // أقل حجم قمت أنت بتحديدة
	char* CaveSectionName;
} CAVE;

```
## كيف تستدعي المكتبة
ادخل <a href="https://github.com/justalghamdi/PE-Miner/tree/master/PE%20LIB">هنا</a>\
و إنسخ الملفين وضمنهما مع ملفات مشروعك \
قم بإستعداء ملف PE.h في ملف مشروعك \
`#include "PE.h"` .

# عن المشروع
هذا المشروع استوحيت فكرته من مشروع <a href="https://github.com/ins1gn1a/Frampton">Frampton</a> \
يعيب مشروع  <a href="https://github.com/ins1gn1a/Frampton">Frampton</a> أنه بطيئ جدا مع الملفات الكبيرة يأخذ مابين 3 دقائق الى 4 دقائق ليحقن شيل كود في داخل برنامج مثل Discord\
ويستهلك مايقارب 1GB من الذاكرة!!! \
وهذا العيب بسبب اللغة المستعملة في المشروع بايثون \
لذلك اردت أنا بناء نفس المشروع لكن بلغة C للسرعة والخفه مع سورس بسيط وبدون تعقيد \
وايضا محاكاة لمكتبة pefile في بايثون 
# متطلبات
برنامج : Visual Studio\
"البيئة التطويرية"
--------------------------------------------------
يمكنك تحميل نسخة Release من <a href="https://github.com/justalghamdi/PE-Miner/releases/tag/Release"> هنا </a>
