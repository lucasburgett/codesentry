function renderHtml(content: string) {
  return <div dangerouslySetInnerHTML={{ __html: content }} />;
}
