use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, AttributeArgs, ItemFn, Meta, NestedMeta};

#[proc_macro_attribute]
pub fn integration_test(attr: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attr as AttributeArgs);
    let item = parse_macro_input!(item as ItemFn);

    let ItemFn {
        attrs, vis, sig, ..
    } = &item;
    let name = &sig.ident;
    let name_str = &sig.ident.to_string();

    // Wrap in a netns exec
    let netns = args
        .iter()
        .any(|arg| matches!(arg, NestedMeta::Meta(Meta::Path(path)) if path.is_ident("netns")));
    let item = if netns {
        // A vec cannot be directly expanded, and an empty #[] yields errors...
        let attrs = if attrs.is_empty() {
            quote!()
        } else {
            quote!(#[#(#attrs),*])
        };
        quote! {
            #attrs
            #vis #sig {
                #item
                let netns = crate::utils::Netns::new();
                netns.exec(|| #name());
            }
        }
    } else {
        quote!(#item)
    };

    let expanded = quote! {
        #item

        inventory::submit!(IntegrationTest {
            name: concat!(module_path!(), "::", #name_str),
            test_fn: #name,
        });
    };
    TokenStream::from(expanded)
}
