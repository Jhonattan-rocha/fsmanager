// Estado efêmero do drag-and-drop INTERNO (mover itens entre pastas).
// Singleton de módulo: o FileTable preenche em dragstart; FileTable e
// Breadcrumbs leem no drop. Não é estado de React (não dispara re-render).
export const dragState = {
  items: [] as string[],
};
