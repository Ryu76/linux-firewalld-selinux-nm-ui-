# Frontend (`controller/static/`) Guidelines

이 규칙은 `controller/static/` 하위 프론트엔드 파일을 수정할 때만 적용됩니다.

1. **브라우저 캐시 무효화**: `style.css` 또는 `app.js`를 수정한 경우 반드시 `index.html`의 `?v=N` 쿼리 버전을 1씩 올립니다.
2. **다크 테마 일관성**:
   - 커스텀 버튼에는 `appearance: none; -webkit-appearance: none;`을 유지해 브라우저 기본 스타일이 섞이지 않도록 합니다.
   - 목록성 데이터(`Services`, `Ports`, `ICMP Filter`, `Sources & Interfaces`)는 칩(chip) 나열 대신 1행 테이블(`.table-scroll`, `.grid-2`) 구조를 사용합니다.
3. **즉시 상태 갱신**:
   - 모든 `fetch` 호출에는 `cache: "no-store"`를 유지합니다.
   - 사용자 수동 조작(`runAction`, `refreshAll`)은 백그라운드 폴링(`isLoading`)에 의해 무시되지 않고 `loadActiveStatus()`를 즉시 호출해야 합니다.
