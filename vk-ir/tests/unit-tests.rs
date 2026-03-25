#[cfg(test)]
mod tests {
    use vk_ir::*;
    use std::collections::HashMap;


    fn default_metadata() -> Metadata {
        Metadata {
            source: None,
            symbol: None,
            taint: TaintState::default(),
            tags: HashMap::new(),
        }
    }

    #[test]
    fn test_instruction_metadata_attachment() {
        let mut meta = default_metadata();
        meta.source = Some(SourceLocation {
            file: "main.js".to_string(),
            line: 10,
            column: 5,
        });
        meta.symbol = Some(SymbolId(42));
        meta.taint = TaintState::tainted(TaintKind::UserInput);
        meta.tags.insert("user_input".to_string(), "true".to_string());

        let instr = Annotated {
            node: Instruction::Return {
                value: Some(Annotated {
                    node: Expr::Identifier("x".to_string()),
                    meta: default_metadata(),
                }),
            },
            meta,
        };

        assert_eq!(instr.meta.source.as_ref().unwrap().file, "main.js");
        assert_eq!(instr.meta.source.as_ref().unwrap().line, 10);
        assert_eq!(instr.meta.symbol.unwrap(), SymbolId(42));
        assert!(instr.meta.taint.is_tainted());
        assert_eq!(instr.meta.tags.get("user_input").unwrap(), "true");
    }

    #[test]
    fn test_expression_metadata_propagation() {
        let mut meta = default_metadata();
        meta.taint = TaintState::tainted(TaintKind::UserInput);

        let expr = Annotated {
            node: Expr::Call {
                callee: Box::new(AExpr {
                    node: Expr::Identifier("eval".to_string()),
                    meta: default_metadata(),
                }),
                args: vec![AExpr {
                    node: Expr::Identifier("userInput".to_string()),
                    meta: meta.clone(),
                }],
            },
            meta: meta.clone(),
        };

        if let Expr::Call { args, .. } = &expr.node {
            assert!(args[0].meta.taint.is_tainted());
        } else {
            panic!("Expected Call expression");
        }
    }

    #[test]
    fn test_arbitrary_tags_on_ir_nodes() {
        let mut meta = default_metadata();
        meta.tags.insert("sink".to_string(), "sql".to_string());
        meta.tags.insert("severity".to_string(), "high".to_string());

        let instr = Annotated {
            node: Instruction::Call {
                callee: AExpr {
                    node: Expr::Identifier("executeQuery".to_string()),
                    meta: default_metadata(),
                },
                args: vec![],
            },
            meta,
        };

        assert_eq!(instr.meta.tags.get("sink").unwrap(), "sql");
        assert_eq!(instr.meta.tags.get("severity").unwrap(), "high");
    }

    #[test]
    fn test_symbol_table_add_and_lookup() {
        let mut table = SymbolTable::new();
        let scope = ScopeId(1);

        let id1 = table.add_symbol("userInput".to_string(), SymbolKind::Variable, scope);
        let _id2 = table.add_symbol("userInput".to_string(), SymbolKind::Parameter, scope);

        let symbols = table.find_symbols("userInput");
        assert_eq!(symbols.len(), 2);

        let sym = table.get_symbol(id1).unwrap();
        assert_eq!(sym.name, "userInput");
        assert_eq!(sym.scope_id, scope);
        assert_eq!(sym.kind, SymbolKind::Variable);
    }

    #[test]
    fn test_module_graph_dependency_tracking() {
        let mut graph = ModuleGraph::new();
        graph.add_dependency("src/a.js", "src/b.js");
        graph.add_dependency("src/a.js", "src/c.js");

        let deps = graph.get_dependencies("src/a.js");
        assert_eq!(deps.len(), 2);
        assert!(deps.contains(&"src/b.js".to_string()));
        assert!(deps.contains(&"src/c.js".to_string()));

        let dependents = graph.get_dependents("src/b.js");
        assert_eq!(dependents, &["src/a.js".to_string()]);
    }

    #[test]
    fn test_cfg_branch_and_jump() {
        let block1 = BlockId(1);
        let block2 = BlockId(2);
        let block3 = BlockId(3);

        let cond_expr = AExpr {
            node: Expr::Binary {
                op: BinaryOp::Equal,
                left: Box::new(AExpr {
                    node: Expr::Identifier("x".to_string()),
                    meta: default_metadata(),
                }),
                right: Box::new(AExpr {
                    node: Expr::Literal(Value::Number(0.0)),
                    meta: default_metadata(),
                }),
            },
            meta: default_metadata(),
        };

        let branch_instr = Annotated {
            node: Instruction::Branch {
                condition: cond_expr,
                then_block: block2,
                else_block: block3,
            },
            meta: default_metadata(),
        };

        let jump_instr = Annotated {
            node: Instruction::Jump {
                target: block1,
            },
            meta: default_metadata(),
        };

        match &branch_instr.node {
            Instruction::Branch { then_block, else_block, .. } => {
                assert_eq!(*then_block, block2);
                assert_eq!(*else_block, block3);
            }
            _ => panic!("Expected Branch instruction"),
        }

        match &jump_instr.node {
            Instruction::Jump { target } => {
                assert_eq!(*target, block1);
            }
            _ => panic!("Expected Jump instruction"),
        }
    }

    #[test]
    fn test_return_with_and_without_value() {
        let ret_with_value = AInstruction {
            node: Instruction::Return {
                value: Some(AExpr {
                    node: Expr::Literal(Value::String("ok".to_string())),
                    meta: default_metadata(),
                }),
            },
            meta: default_metadata(),
        };
        

        let ret_without_value = AInstruction {
            node: Instruction::Return { value: None },
            meta: default_metadata(),
        };
        

        match &ret_with_value.node {
            Instruction::Return { value } => {
                assert!(value.is_some());
            }
            _ => panic!("Expected Return instruction"),
        }

        match &ret_without_value.node {
            Instruction::Return { value } => {
                assert!(value.is_none());
            }
            _ => panic!("Expected Return instruction"),
        }
    }

    #[test]
    fn test_string_concatenation_expression() {
        let expr = AExpr {
            node: Expr::Binary {
                op: BinaryOp::Concat,
                left: Box::new(AExpr {
                    node: Expr::Literal(Value::String("Hello ".to_string())),
                    meta: default_metadata(),
                }),
                right: Box::new(AExpr {
                    node: Expr::Identifier("name".to_string()),
                    meta: default_metadata(),
                }),
            },
            meta: default_metadata(),
        };

        if let Expr::Binary { op, .. } = &expr.node {
            assert_eq!(*op, BinaryOp::Concat);
        } else {
            panic!("Expected Binary Concat expression");
        }
    }

    #[test]
    fn test_taint_initially_empty() {
        let meta = default_metadata();
        assert!(!meta.taint.is_tainted());
        assert!(meta.tags.is_empty());
        assert!(meta.source.is_none());
        assert!(meta.symbol.is_none());
    }

    #[test]
    fn test_function_with_blocks_and_entry() {
        let entry = BlockId(0);
        let block = BasicBlock {
            id: entry,
            instructions: vec![],
        };

        let function = Function {
            name: "testFunc".to_string(),
            params: vec![],
            blocks: vec![block],
            entry_block: entry,
            scope_id: ScopeId(0),
        };

        assert_eq!(function.entry_block, entry);
        assert_eq!(function.blocks.len(), 1);
        assert_eq!(function.blocks[0].id, entry);
    }
}
