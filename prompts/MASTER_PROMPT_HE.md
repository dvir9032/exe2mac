# פרומפט ראשי לסוכן AI — exe2mac

אתה סוכן פיתוח בכיר שמתבקש להמשיך פרויקט קיים בשם `exe2mac`. עבוד על הקבצים שבמאגר עצמו; אל תסתפק בהמלצות או במסמכי תכנון. המטרה היא לממש static recompilation של קובצי Windows PE32+ x86-64 לקוד native עבור macOS ARM64, ללא Wine וללא אמולציית CPU בזמן ריצה.

## הקשר
קובץ הבדיקה הראשון הוא `test/hello.exe`, והמקור שלו הוא `test/hello.c`. המימוש הקיים כולל:
- `recompiler/pe.py` — קריאת PE32+.
- `recompiler/disasm.py` — פענוח דרך `objdump`.
- `recompiler/analysis.py` — ניתוח בסיסי של CFG, קפיצות, RIP-relative ו־IAT.
- `recompiler/analyze_cli.py` — דוח JSON.
- `runtime/winapi_shims.c/.h` — shims ראשוניים עבור `GetStdHandle`, `WriteFile`, `ExitProcess`.
- `recompiler/translate.py` כרגע בכוונה נכשל עם `TranslationError`; תרגום אמיתי עדיין לא מומש.
- `tests/` — 7 בדיקות קיימות.

קרא תחילה את `AGENTS.md`, את כל הקבצים הרלוונטיים, ובפרט את `test/hello.c`. אמת בעצמך את פלט התוכנית ואת קוד היציאה הצפוי.

## משימה
המשך מהמימוש הקיים והפוך אותו למתרגם עובד בשלבים קטנים, עד כמה שהסביבה מאפשרת. אל תעצור אחרי כתיבת תוכנית עבודה. בצע שינויים בקוד, הוסף בדיקות, הרץ אותן, ועדכן מסמכים.

## דרישות קריטיות
1. אל תעמיד פנים שקיימת תמיכה בהוראה אם הסמנטיקה שלה אינה ממומשת במדויק.
2. כל הוראה לא נתמכת, import לא מוכר, relocation לא נתמך או יעד קפיצה לא פתור חייבים להפיק שגיאה ברורה ולא להפוך ל־no-op.
3. ייצג במפורש מצב אורח: רגיסטרים, דגלים, זיכרון, מחסנית, כתובות ו־Windows x64 ABI. אל תשתמש ישירות ב־host ABI עבור קריאות אורח.
4. הקפד על רוחבי אופרנדים, zero-extension בכתיבה לרגיסטר 32-bit, partial registers, overflow ו־undefined behavior של C. השתמש בטיפוסים unsigned וב־helpers מדויקים לחישובי bit-level.
5. הוסף unit tests לכל סמנטיקת הוראה ולדגלים. הוסף integration tests שמריצים בפועל את התוצר כאשר הפלטפורמה מאפשרת.
6. אל תעתיק קוד נרחב מפרויקטים אחרים. מותר ללמוד ארכיטקטורה מ־N64Recomp ו־Remill, ולהשתמש ב־Capstone כתלות בכפוף לרישיון שלו.
7. אם סביבת העבודה אינה macOS ARM64, אל תטען שבנית או הרצת את התוצר ל־macOS. כתוב במפורש אילו בדיקות לא ניתן לבצע כאן.

## סדר עבודה מומלץ
שלב א — baseline:
- הרץ `python3 -m unittest discover -s tests -v`.
- בדוק את ה־PE, ה־imports, ה־relocations, כתובות הפונקציות וה־disassembly.
- בדוק את `hello.c` והפק מפרט של הפלט המדויק וקוד היציאה.

שלב ב — מודל ביניים:
- צור ייצוג מובנה להוראות ולאופרנדים, לבלוקים בסיסיים ולקצוות CFG.
- הימנע מתלות בפריסת הטקסט של `objdump`; אם אפשר, הוסף decoder מבוסס Capstone עם fallback או שגיאה ברורה.
- זהה את הקוד הנגיש בפועל מה־entry point, פונקציות, import thunks וקפיצות עקיפות.

שלב ג — semantics:
- ממש תחילה helpers מדויקים ל־registers, memory, stack ו־flags.
- ממש את כל ההוראות הנגישות ב־`hello.exe`, כולל בין היתר `mov`, `lea`, `call`, `ret`, `cmp`, `jcc`, `push`, `pop`, `mul`, `imul`, `idiv`, `cdq`, `cmovs`, `movsxd`, `add`, `sub`, `xor`, `test`, `inc`, `dec`, `neg`, `or`, `shr`, `xchg`, ו־`nop`, אך רק לאחר בדיקת המלאי האמיתי.
- מימוש התנאים חייב להתבסס על דגלים מחושבים נכון, לא על קירוב.
- בנה backend ל־C או LLVM IR. בחר בפתרון הפשוט ביותר שניתן לבדוק, ושמור את ה־IR נפרד מה־backend.

שלב ד — loader ו־runtime:
- מיפוי PE sections ו־image base, זיכרון אורח, relocations, imports ו־IAT.
- טיפול עקבי בכתובות אורח ובקריאות/חזרות בלי לערבב return addresses אורחים עם כתובות חזרה של ה־host.
- bridge נכון מ־Windows x64 ABI ל־host ABI עבור `GetStdHandle`, `WriteFile`, `ExitProcess`.
- `ExitProcess` צריך לסיים את התהליך עם קוד היציאה האורח, כולל נתיב שאינו חוזר.

שלב ה — build ובדיקת golden:
- צור פקודת CLI אחת ברורה, לדוגמה `python3 -m recompiler ...`.
- צור golden stdout מתוך המקור/הרצה מקורית מאומתת; אל תמציא פלט צפוי.
- בנה והריץ את התוצר ב־macOS ARM64 אם זמין.
- השווה stdout כבתים, בדוק stderr בנפרד וקוד יציאה מדויק.
- הוסף CI או הוראות בדיקה חוזרות ככל האפשר.

## שימוש בפרויקטים חיצוניים
- N64Recomp: ללמוד מבנה pipeline של static recompilation; לא להניח ש־MIPS semantics מתאימות ל־x86-64.
- Remill: ללמוד איך לתאר סמנטיקה של הוראות x86-64 ומצב המעבד; הוא מרים ל־LLVM IR ולא מספק ישירות backend C פשוט.
- Capstone: decoder מבני של הוראות ואופרנדים; הוא אינו recompiler.

קישורים:
- https://github.com/N64Recomp/N64Recomp
- https://github.com/lifting-bits/remill
- https://github.com/capstone-engine/capstone

בדוק רישיונות ותלויות לפני הוספת קוד או ספריות.

## עדכונים ודיווח
בצע עבודה ברצף, ועדכן אחרי כל אבן דרך משמעותית. כל עדכון חייב לכלול:
- מה שינית וקבצים שנוספו/עודכנו.
- אילו פקודות הרצת ותוצאות אמיתיות (מספר passed/failed).
- האם נבנה קובץ native, על איזו מערכת וארכיטקטורה.
- האם התוכנית שנוצרה הורצה בפועל.
- האם stdout הושווה byte-for-byte ומה היה קוד היציאה.
- חסמים ומה הצעד הבא.

אל תדווח הצלחה על סמך קוד שנראה נכון בלבד. אם נתקעת, נסה לפתור את החסם, צמצם את הבעיה, הוסף בדיקת רגרסיה, והמשך לעבוד. אל תעצור אחרי מסמך תכנון בלבד.
