#define ToLower(Char) ((Char >= 'A' && Char <= 'Z') ? (Char + 32) : Char)

template <typename StrType>
__forceinline int StrLen(StrType Str) {
	if (!Str) return 0;
	StrType Str2 = Str;
	while (*Str2) Str2++;
	return (int)(Str2 - Str);
}

template <typename StrType, typename StrType2>
__forceinline bool StrCmp(StrType Str, StrType2 InStr, bool Two) {
	if (!Str || !InStr)
		return false;
	wchar_t c1, c2; do {
		c1 = *Str++; c2 = *InStr++;
		c1 = ToLower(c1); c2 = ToLower(c2);
		if (!c1 && (Two ? !c2 : 1)) return true;
	} while (c1 == c2); return false;
}

template <typename StrType, typename StrType2>
__forceinline void StrCpy(StrType Src, StrType2 Dst, wchar_t TNull = 0) {
	if (!Src || !Dst) return;
	while (true) {
		wchar_t WChar = *Dst = *Src++;
		if (WChar == TNull) {
			*Dst = 0; break;
		} Dst++;
	}
}

template <typename StrType, typename StrType2>
__forceinline void StrCat(StrType ToStr, StrType2 Str) {
	StrCpy(Str, (StrType)&ToStr[StrLen(ToStr)]);
}