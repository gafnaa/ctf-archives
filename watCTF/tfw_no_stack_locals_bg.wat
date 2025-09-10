(module
  (type (;0;) (func (param i32 i32) (result i32)))
  (type (;1;) (func (param i32 i32)))
  (type (;2;) (func (param i32 i32 i32) (result i32)))
  (type (;3;) (func (param i32)))
  (type (;4;) (func (param i32 i32 i32)))
  (type (;5;) (func (param i32 i32 i32 i32) (result i32)))
  (type (;6;) (func))
  (type (;7;) (func (param i32) (result i32)))
  (type (;8;) (func (param i32 i32 i32 i32 i32)))
  (import "wbg" "__wbindgen_init_externref_table" (func (;0;) (type 6)))
  (func (;1;) (type 7) (param i32) (result i32)
    (local i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i64)
    global.get 0
    i32.const 16
    i32.sub
    local.tee 9
    global.set 0
    block  ;; label = @1
      block  ;; label = @2
        block  ;; label = @3
          block  ;; label = @4
            block  ;; label = @5
              block  ;; label = @6
                block  ;; label = @7
                  local.get 0
                  i32.const 245
                  i32.ge_u
                  if  ;; label = @8
                    local.get 0
                    i32.const -65588
                    i32.gt_u
                    br_if 7 (;@1;)
                    local.get 0
                    i32.const 11
                    i32.add
                    local.tee 2
                    i32.const -8
                    i32.and
                    local.set 5
                    i32.const 1050688
                    i32.load
                    local.tee 8
                    i32.eqz
                    br_if 4 (;@4;)
                    i32.const 31
                    local.set 7
                    local.get 0
                    i32.const 16777204
                    i32.le_u
                    if  ;; label = @9
                      local.get 5
                      i32.const 6
                      local.get 2
                      i32.const 8
                      i32.shr_u
                      i32.clz
                      local.tee 0
                      i32.sub
                      i32.shr_u
                      i32.const 1
                      i32.and
                      local.get 0
                      i32.const 1
                      i32.shl
                      i32.sub
                      i32.const 62
                      i32.add
                      local.set 7
                    end
                    i32.const 0
                    local.get 5
                    i32.sub
                    local.set 0
                    local.get 7
                    i32.const 2
                    i32.shl
                    i32.const 1050276
                    i32.add
                    i32.load
                    local.tee 2
                    i32.eqz
                    br_if 1 (;@7;)
                    local.get 5
                    i32.const 25
                    local.get 7
                    i32.const 1
                    i32.shr_u
                    i32.sub
                    i32.const 0
                    local.get 7
                    i32.const 31
                    i32.ne
                    select
                    i32.shl
                    local.set 4
                    loop  ;; label = @9
                      block  ;; label = @10
                        local.get 2
                        i32.load offset=4
                        i32.const -8
                        i32.and
                        local.tee 6
                        local.get 5
                        i32.lt_u
                        br_if 0 (;@10;)
                        local.get 6
                        local.get 5
                        i32.sub
                        local.tee 6
                        local.get 0
                        i32.ge_u
                        br_if 0 (;@10;)
                        local.get 2
                        local.set 3
                        local.get 6
                        local.tee 0
                        br_if 0 (;@10;)
                        i32.const 0
                        local.set 0
                        local.get 2
                        local.set 1
                        br 4 (;@6;)
                      end
                      local.get 2
                      i32.load offset=20
                      local.tee 6
                      local.get 1
                      local.get 6
                      local.get 2
                      local.get 4
                      i32.const 29
                      i32.shr_u
                      i32.const 4
                      i32.and
                      i32.add
                      i32.load offset=16
                      local.tee 2
                      i32.ne
                      select
                      local.get 1
                      local.get 6
                      select
                      local.set 1
                      local.get 4
                      i32.const 1
                      i32.shl
                      local.set 4
                      local.get 2
                      br_if 0 (;@9;)
                    end
                    br 1 (;@7;)
                  end
                  i32.const 1050684
                  i32.load
                  local.tee 2
                  i32.const 16
                  local.get 0
                  i32.const 11
                  i32.add
                  i32.const 504
                  i32.and
                  local.get 0
                  i32.const 11
                  i32.lt_u
                  select
                  local.tee 5
                  i32.const 3
                  i32.shr_u
                  local.tee 0
                  i32.shr_u
                  local.tee 1
                  i32.const 3
                  i32.and
                  if  ;; label = @8
                    block  ;; label = @9
                      local.get 1
                      i32.const -1
                      i32.xor
                      i32.const 1
                      i32.and
                      local.get 0
                      i32.add
                      local.tee 6
                      i32.const 3
                      i32.shl
                      local.tee 1
                      i32.const 1050276
                      i32.add
                      local.tee 0
                      i32.const 144
                      i32.add
                      local.tee 3
                      local.get 0
                      i32.load offset=152
                      local.tee 0
                      i32.load offset=8
                      local.tee 4
                      i32.ne
                      if  ;; label = @10
                        local.get 4
                        local.get 3
                        i32.store offset=12
                        local.get 3
                        local.get 4
                        i32.store offset=8
                        br 1 (;@9;)
                      end
                      i32.const 1050684
                      local.get 2
                      i32.const -2
                      local.get 6
                      i32.rotl
                      i32.and
                      i32.store
                    end
                    local.get 0
                    i32.const 8
                    i32.add
                    local.set 3
                    local.get 0
                    local.get 1
                    i32.const 3
                    i32.or
                    i32.store offset=4
                    local.get 0
                    local.get 1
                    i32.add
                    local.tee 0
                    local.get 0
                    i32.load offset=4
                    i32.const 1
                    i32.or
                    i32.store offset=4
                    br 7 (;@1;)
                  end
                  local.get 5
                  i32.const 1050692
                  i32.load
                  i32.le_u
                  br_if 3 (;@4;)
                  block  ;; label = @8
                    block  ;; label = @9
                      local.get 1
                      i32.eqz
                      if  ;; label = @10
                        i32.const 1050688
                        i32.load
                        local.tee 0
                        i32.eqz
                        br_if 6 (;@4;)
                        local.get 0
                        i32.ctz
                        i32.const 2
                        i32.shl
                        i32.const 1050276
                        i32.add
                        i32.load
                        local.tee 3
                        i32.load offset=4
                        i32.const -8
                        i32.and
                        local.get 5
                        i32.sub
                        local.set 0
                        local.get 3
                        local.set 2
                        loop  ;; label = @11
                          block  ;; label = @12
                            local.get 3
                            i32.load offset=16
                            local.tee 1
                            br_if 0 (;@12;)
                            local.get 3
                            i32.load offset=20
                            local.tee 1
                            br_if 0 (;@12;)
                            local.get 2
                            i32.load offset=24
                            local.set 7
                            block  ;; label = @13
                              block  ;; label = @14
                                local.get 2
                                local.get 2
                                i32.load offset=12
                                local.tee 1
                                i32.eq
                                if  ;; label = @15
                                  local.get 2
                                  i32.const 20
                                  i32.const 16
                                  local.get 2
                                  i32.load offset=20
                                  local.tee 1
                                  select
                                  i32.add
                                  i32.load
                                  local.tee 3
                                  br_if 1 (;@14;)
                                  i32.const 0
                                  local.set 1
                                  br 2 (;@13;)
                                end
                                local.get 2
                                i32.load offset=8
                                local.tee 3
                                local.get 1
                                i32.store offset=12
                                local.get 1
                                local.get 3
                                i32.store offset=8
                                br 1 (;@13;)
                              end
                              local.get 2
                              i32.const 20
                              i32.add
                              local.get 2
                              i32.const 16
                              i32.add
                              local.get 1
                              select
                              local.set 4
                              loop  ;; label = @14
                                local.get 4
                                local.set 6
                                local.get 3
                                local.tee 1
                                i32.const 20
                                i32.add
                                local.get 1
                                i32.const 16
                                i32.add
                                local.get 1
                                i32.load offset=20
                                local.tee 3
                                select
                                local.set 4
                                local.get 1
                                i32.const 20
                                i32.const 16
                                local.get 3
                                select
                                i32.add
                                i32.load
                                local.tee 3
                                br_if 0 (;@14;)
                              end
                              local.get 6
                              i32.const 0
                              i32.store
                            end
                            local.get 7
                            i32.eqz
                            br_if 4 (;@8;)
                            block  ;; label = @13
                              local.get 2
                              i32.load offset=28
                              local.tee 3
                              i32.const 2
                              i32.shl
                              i32.const 1050276
                              i32.add
                              local.tee 4
                              i32.load
                              local.get 2
                              i32.ne
                              if  ;; label = @14
                                local.get 2
                                local.get 7
                                i32.load offset=16
                                i32.ne
                                if  ;; label = @15
                                  local.get 7
                                  local.get 1
                                  i32.store offset=20
                                  local.get 1
                                  br_if 2 (;@13;)
                                  br 7 (;@8;)
                                end
                                local.get 7
                                local.get 1
                                i32.store offset=16
                                local.get 1
                                br_if 1 (;@13;)
                                br 6 (;@8;)
                              end
                              local.get 4
                              local.get 1
                              i32.store
                              local.get 1
                              i32.eqz
                              br_if 4 (;@9;)
                            end
                            local.get 1
                            local.get 7
                            i32.store offset=24
                            local.get 2
                            i32.load offset=16
                            local.tee 3
                            if  ;; label = @13
                              local.get 1
                              local.get 3
                              i32.store offset=16
                              local.get 3
                              local.get 1
                              i32.store offset=24
                            end
                            local.get 2
                            i32.load offset=20
                            local.tee 3
                            i32.eqz
                            br_if 4 (;@8;)
                            local.get 1
                            local.get 3
                            i32.store offset=20
                            local.get 3
                            local.get 1
                            i32.store offset=24
                            br 4 (;@8;)
                          end
                          local.get 1
                          i32.load offset=4
                          i32.const -8
                          i32.and
                          local.get 5
                          i32.sub
                          local.tee 3
                          local.get 0
                          local.get 0
                          local.get 3
                          i32.gt_u
                          local.tee 3
                          select
                          local.set 0
                          local.get 1
                          local.get 2
                          local.get 3
                          select
                          local.set 2
                          local.get 1
                          local.set 3
                          br 0 (;@11;)
                        end
                        unreachable
                      end
                      block  ;; label = @10
                        i32.const 2
                        local.get 0
                        i32.shl
                        local.tee 3
                        i32.const 0
                        local.get 3
                        i32.sub
                        i32.or
                        local.get 1
                        local.get 0
                        i32.shl
                        i32.and
                        i32.ctz
                        local.tee 6
                        i32.const 3
                        i32.shl
                        local.tee 3
                        i32.const 1050420
                        i32.add
                        local.tee 1
                        local.get 1
                        i32.load offset=8
                        local.tee 0
                        i32.load offset=8
                        local.tee 4
                        i32.ne
                        if  ;; label = @11
                          local.get 4
                          local.get 1
                          i32.store offset=12
                          local.get 1
                          local.get 4
                          i32.store offset=8
                          br 1 (;@10;)
                        end
                        i32.const 1050684
                        local.get 2
                        i32.const -2
                        local.get 6
                        i32.rotl
                        i32.and
                        i32.store
                      end
                      local.get 0
                      local.get 5
                      i32.const 3
                      i32.or
                      i32.store offset=4
                      local.get 0
                      local.get 5
                      i32.add
                      local.tee 6
                      local.get 3
                      local.get 5
                      i32.sub
                      local.tee 4
                      i32.const 1
                      i32.or
                      i32.store offset=4
                      local.get 0
                      local.get 3
                      i32.add
                      local.get 4
                      i32.store
                      i32.const 1050692
                      i32.load
                      local.tee 3
                      if  ;; label = @10
                        local.get 3
                        i32.const -8
                        i32.and
                        i32.const 1050420
                        i32.add
                        local.set 1
                        i32.const 1050700
                        i32.load
                        local.set 2
                        block (result i32)  ;; label = @11
                          i32.const 1050684
                          i32.load
                          local.tee 5
                          i32.const 1
                          local.get 3
                          i32.const 3
                          i32.shr_u
                          i32.shl
                          local.tee 3
                          i32.and
                          i32.eqz
                          if  ;; label = @12
                            i32.const 1050684
                            local.get 3
                            local.get 5
                            i32.or
                            i32.store
                            local.get 1
                            br 1 (;@11;)
                          end
                          local.get 1
                          i32.load offset=8
                        end
                        local.set 3
                        local.get 1
                        local.get 2
                        i32.store offset=8
                        local.get 3
                        local.get 2
                        i32.store offset=12
                        local.get 2
                        local.get 1
                        i32.store offset=12
                        local.get 2
                        local.get 3
                        i32.store offset=8
                      end
                      local.get 0
                      i32.const 8
                      i32.add
                      local.set 3
                      i32.const 1050700
                      local.get 6
                      i32.store
                      i32.const 1050692
                      local.get 4
                      i32.store
                      br 8 (;@1;)
                    end
                    i32.const 1050688
                    i32.const 1050688
                    i32.load
                    i32.const -2
                    local.get 3
                    i32.rotl
                    i32.and
                    i32.store
                  end
                  block  ;; label = @8
                    block  ;; label = @9
                      local.get 0
                      i32.const 16
                      i32.ge_u
                      if  ;; label = @10
                        local.get 2
                        local.get 5
                        i32.const 3
                        i32.or
                        i32.store offset=4
                        local.get 2
                        local.get 5
                        i32.add
                        local.tee 4
                        local.get 0
                        i32.const 1
                        i32.or
                        i32.store offset=4
                        local.get 0
                        local.get 4
                        i32.add
                        local.get 0
                        i32.store
                        i32.const 1050692
                        i32.load
                        local.tee 6
                        i32.eqz
                        br_if 1 (;@9;)
                        local.get 6
                        i32.const -8
                        i32.and
                        i32.const 1050420
                        i32.add
                        local.set 1
                        i32.const 1050700
                        i32.load
                        local.set 3
                        block (result i32)  ;; label = @11
                          i32.const 1050684
                          i32.load
                          local.tee 5
                          i32.const 1
                          local.get 6
                          i32.const 3
                          i32.shr_u
                          i32.shl
                          local.tee 6
                          i32.and
                          i32.eqz
                          if  ;; label = @12
                            i32.const 1050684
                            local.get 5
                            local.get 6
                            i32.or
                            i32.store
                            local.get 1
                            br 1 (;@11;)
                          end
                          local.get 1
                          i32.load offset=8
                        end
                        local.set 6
                        local.get 1
                        local.get 3
                        i32.store offset=8
                        local.get 6
                        local.get 3
                        i32.store offset=12
                        local.get 3
                        local.get 1
                        i32.store offset=12
                        local.get 3
                        local.get 6
                        i32.store offset=8
                        br 1 (;@9;)
                      end
                      local.get 2
                      local.get 0
                      local.get 5
                      i32.add
                      local.tee 0
                      i32.const 3
                      i32.or
                      i32.store offset=4
                      local.get 0
                      local.get 2
                      i32.add
                      local.tee 0
                      local.get 0
                      i32.load offset=4
                      i32.const 1
                      i32.or
                      i32.store offset=4
                      br 1 (;@8;)
                    end
                    i32.const 1050700
                    local.get 4
                    i32.store
                    i32.const 1050692
                    local.get 0
                    i32.store
                  end
                  local.get 2
                  i32.const 8
                  i32.add
                  local.set 3
                  br 6 (;@1;)
                end
                local.get 1
                local.get 3
                i32.or
                i32.eqz
                if  ;; label = @7
                  i32.const 0
                  local.set 3
                  i32.const 2
                  local.get 7
                  i32.shl
                  local.tee 1
                  i32.const 0
                  local.get 1
                  i32.sub
                  i32.or
                  local.get 8
                  i32.and
                  local.tee 1
                  i32.eqz
                  br_if 3 (;@4;)
                  local.get 1
                  i32.ctz
                  i32.const 2
                  i32.shl
                  i32.const 1050276
                  i32.add
                  i32.load
                  local.set 1
                end
                local.get 1
                i32.eqz
                br_if 1 (;@5;)
              end
              loop  ;; label = @6
                local.get 1
                local.get 3
                local.get 1
                i32.load offset=4
                i32.const -8
                i32.and
                local.tee 4
                local.get 5
                i32.sub
                local.tee 6
                local.get 0
                i32.lt_u
                local.tee 7
                select
                local.set 8
                local.get 1
                i32.load offset=16
                local.tee 2
                i32.eqz
                if  ;; label = @7
                  local.get 1
                  i32.load offset=20
                  local.set 2
                end
                local.get 3
                local.get 8
                local.get 4
                local.get 5
                i32.lt_u
                local.tee 1
                select
                local.set 3
                local.get 0
                local.get 6
                local.get 0
                local.get 7
                select
                local.get 1
                select
                local.set 0
                local.get 2
                local.tee 1
                br_if 0 (;@6;)
              end
            end
            local.get 3
            i32.eqz
            br_if 0 (;@4;)
            local.get 5
            i32.const 1050692
            i32.load
            local.tee 1
            i32.le_u
            local.get 0
            local.get 1
            local.get 5
            i32.sub
            i32.ge_u
            i32.and
            br_if 0 (;@4;)
            local.get 3
            i32.load offset=24
            local.set 7
            block  ;; label = @5
              block  ;; label = @6
                local.get 3
                local.get 3
                i32.load offset=12
                local.tee 1
                i32.eq
                if  ;; label = @7
                  local.get 3
                  i32.const 20
                  i32.const 16
                  local.get 3
                  i32.load offset=20
                  local.tee 1
                  select
                  i32.add
                  i32.load
                  local.tee 2
                  br_if 1 (;@6;)
                  i32.const 0
                  local.set 1
                  br 2 (;@5;)
                end
                local.get 3
                i32.load offset=8
                local.tee 2
                local.get 1
                i32.store offset=12
                local.get 1
                local.get 2
                i32.store offset=8
                br 1 (;@5;)
              end
              local.get 3
              i32.const 20
              i32.add
              local.get 3
              i32.const 16
              i32.add
              local.get 1
              select
              local.set 4
              loop  ;; label = @6
                local.get 4
                local.set 6
                local.get 2
                local.tee 1
                i32.const 20
                i32.add
                local.get 1
                i32.const 16
                i32.add
                local.get 1
                i32.load offset=20
                local.tee 2
                select
                local.set 4
                local.get 1
                i32.const 20
                i32.const 16
                local.get 2
                select
                i32.add
                i32.load
                local.tee 2
                br_if 0 (;@6;)
              end
              local.get 6
              i32.const 0
              i32.store
            end
            local.get 7
            i32.eqz
            br_if 2 (;@2;)
            block  ;; label = @5
              local.get 3
              i32.load offset=28
              local.tee 2
              i32.const 2
              i32.shl
              i32.const 1050276
              i32.add
              local.tee 4
              i32.load
              local.get 3
              i32.ne
              if  ;; label = @6
                local.get 3
                local.get 7
                i32.load offset=16
                i32.ne
                if  ;; label = @7
                  local.get 7
                  local.get 1
                  i32.store offset=20
                  local.get 1
                  br_if 2 (;@5;)
                  br 5 (;@2;)
                end
                local.get 7
                local.get 1
                i32.store offset=16
                local.get 1
                br_if 1 (;@5;)
                br 4 (;@2;)
              end
              local.get 4
              local.get 1
              i32.store
              local.get 1
              i32.eqz
              br_if 2 (;@3;)
            end
            local.get 1
            local.get 7
            i32.store offset=24
            local.get 3
            i32.load offset=16
            local.tee 2
            if  ;; label = @5
              local.get 1
              local.get 2
              i32.store offset=16
              local.get 2
              local.get 1
              i32.store offset=24
            end
            local.get 3
            i32.load offset=20
            local.tee 2
            i32.eqz
            br_if 2 (;@2;)
            local.get 1
            local.get 2
            i32.store offset=20
            local.get 2
            local.get 1
            i32.store offset=24
            br 2 (;@2;)
          end
          block  ;; label = @4
            block  ;; label = @5
              block  ;; label = @6
                block  ;; label = @7
                  block  ;; label = @8
                    local.get 5
                    i32.const 1050692
                    i32.load
                    local.tee 1
                    i32.gt_u
                    if  ;; label = @9
                      local.get 5
                      i32.const 1050696
                      i32.load
                      local.tee 0
                      i32.ge_u
                      if  ;; label = @10
                        local.get 5
                        i32.const 65583
                        i32.add
                        i32.const -65536
                        i32.and
                        local.tee 2
                        i32.const 16
                        i32.shr_u
                        memory.grow
                        local.set 0
                        local.get 9
                        i32.const 4
                        i32.add
                        local.tee 1
                        i32.const 0
                        i32.store offset=8
                        local.get 1
                        i32.const 0
                        local.get 2
                        i32.const -65536
                        i32.and
                        local.get 0
                        i32.const -1
                        i32.eq
                        local.tee 2
                        select
                        i32.store offset=4
                        local.get 1
                        i32.const 0
                        local.get 0
                        i32.const 16
                        i32.shl
                        local.get 2
                        select
                        i32.store
                        i32.const 0
                        local.set 3
                        local.get 9
                        i32.load offset=4
                        local.tee 0
                        i32.eqz
                        br_if 9 (;@1;)
                        local.get 9
                        i32.load offset=12
                        local.set 7
                        i32.const 1050708
                        local.get 9
                        i32.load offset=8
                        local.tee 6
                        i32.const 1050708
                        i32.load
                        i32.add
                        local.tee 1
                        i32.store
                        i32.const 1050712
                        local.get 1
                        i32.const 1050712
                        i32.load
                        local.tee 2
                        local.get 1
                        local.get 2
                        i32.gt_u
                        select
                        i32.store
                        i32.const 1050704
                        i32.load
                        local.tee 2
                        i32.eqz
                        if  ;; label = @11
                          i32.const 1050720
                          i32.load
                          local.tee 1
                          i32.const 0
                          local.get 0
                          local.get 1
                          i32.ge_u
                          select
                          i32.eqz
                          if  ;; label = @12
                            i32.const 1050720
                            local.get 0
                            i32.store
                          end
                          i32.const 1050724
                          i32.const 4095
                          i32.store
                          i32.const 1050416
                          local.get 7
                          i32.store
                          i32.const 1050408
                          local.get 6
                          i32.store
                          i32.const 1050404
                          local.get 0
                          i32.store
                          i32.const 1050432
                          i32.const 1050420
                          i32.store
                          i32.const 1050440
                          i32.const 1050428
                          i32.store
                          i32.const 1050428
                          i32.const 1050420
                          i32.store
                          i32.const 1050448
                          i32.const 1050436
                          i32.store
                          i32.const 1050436
                          i32.const 1050428
                          i32.store
                          i32.const 1050456
                          i32.const 1050444
                          i32.store
                          i32.const 1050444
                          i32.const 1050436
                          i32.store
                          i32.const 1050464
                          i32.const 1050452
                          i32.store
                          i32.const 1050452
                          i32.const 1050444
                          i32.store
                          i32.const 1050472
                          i32.const 1050460
                          i32.store
                          i32.const 1050460
                          i32.const 1050452
                          i32.store
                          i32.const 1050480
                          i32.const 1050468
                          i32.store
                          i32.const 1050468
                          i32.const 1050460
                          i32.store
                          i32.const 1050488
                          i32.const 1050476
                          i32.store
                          i32.const 1050476
                          i32.const 1050468
                          i32.store
                          i32.const 1050496
                          i32.const 1050484
                          i32.store
                          i32.const 1050484
                          i32.const 1050476
                          i32.store
                          i32.const 1050492
                          i32.const 1050484
                          i32.store
                          i32.const 1050504
                          i32.const 1050492
                          i32.store
                          i32.const 1050500
                          i32.const 1050492
                          i32.store
                          i32.const 1050512
                          i32.const 1050500
                          i32.store
                          i32.const 1050508
                          i32.const 1050500
                          i32.store
                          i32.const 1050520
                          i32.const 1050508
                          i32.store
                          i32.const 1050516
                          i32.const 1050508
                          i32.store
                          i32.const 1050528
                          i32.const 1050516
                          i32.store
                          i32.const 1050524
                          i32.const 1050516
                          i32.store
                          i32.const 1050536
                          i32.const 1050524
                          i32.store
                          i32.const 1050532
                          i32.const 1050524
                          i32.store
                          i32.const 1050544
                          i32.const 1050532
                          i32.store
                          i32.const 1050540
                          i32.const 1050532
                          i32.store
                          i32.const 1050552
                          i32.const 1050540
                          i32.store
                          i32.const 1050548
                          i32.const 1050540
                          i32.store
                          i32.const 1050560
                          i32.const 1050548
                          i32.store
                          i32.const 1050568
                          i32.const 1050556
                          i32.store
                          i32.const 1050556
                          i32.const 1050548
                          i32.store
                          i32.const 1050576
                          i32.const 1050564
                          i32.store
                          i32.const 1050564
                          i32.const 1050556
                          i32.store
                          i32.const 1050584
                          i32.const 1050572
                          i32.store
                          i32.const 1050572
                          i32.const 1050564
                          i32.store
                          i32.const 1050592
                          i32.const 1050580
                          i32.store
                          i32.const 1050580
                          i32.const 1050572
                          i32.store
                          i32.const 1050600
                          i32.const 1050588
                          i32.store
                          i32.const 1050588
                          i32.const 1050580
                          i32.store
                          i32.const 1050608
                          i32.const 1050596
                          i32.store
                          i32.const 1050596
                          i32.const 1050588
                          i32.store
                          i32.const 1050616
                          i32.const 1050604
                          i32.store
                          i32.const 1050604
                          i32.const 1050596
                          i32.store
                          i32.const 1050624
                          i32.const 1050612
                          i32.store
                          i32.const 1050612
                          i32.const 1050604
                          i32.store
                          i32.const 1050632
                          i32.const 1050620
                          i32.store
                          i32.const 1050620
                          i32.const 1050612
                          i32.store
                          i32.const 1050640
                          i32.const 1050628
                          i32.store
                          i32.const 1050628
                          i32.const 1050620
                          i32.store
                          i32.const 1050648
                          i32.const 1050636
                          i32.store
                          i32.const 1050636
                          i32.const 1050628
                          i32.store
                          i32.const 1050656
                          i32.const 1050644
                          i32.store
                          i32.const 1050644
                          i32.const 1050636
                          i32.store
                          i32.const 1050664
                          i32.const 1050652
                          i32.store
                          i32.const 1050652
                          i32.const 1050644
                          i32.store
                          i32.const 1050672
                          i32.const 1050660
                          i32.store
                          i32.const 1050660
                          i32.const 1050652
                          i32.store
                          i32.const 1050680
                          i32.const 1050668
                          i32.store
                          i32.const 1050668
                          i32.const 1050660
                          i32.store
                          i32.const 1050676
                          i32.const 1050668
                          i32.store
                          i32.const 1050704
                          local.get 0
                          i32.const 15
                          i32.add
                          i32.const -8
                          i32.and
                          local.tee 1
                          i32.const 8
                          i32.sub
                          local.tee 2
                          i32.store
                          local.get 2
                          local.get 6
                          i32.const 40
                          i32.sub
                          local.tee 2
                          local.get 0
                          local.get 1
                          i32.sub
                          i32.add
                          i32.const 8
                          i32.add
                          local.tee 1
                          i32.const 1
                          i32.or
                          i32.store offset=4
                          i32.const 1050696
                          local.get 1
                          i32.store
                          local.get 0
                          local.get 2
                          i32.add
                          i32.const 40
                          i32.store offset=4
                          i32.const 1050716
                          i32.const 2097152
                          i32.store
                          br 7 (;@4;)
                        end
                        i32.const 1050404
                        local.set 1
                        block  ;; label = @11
                          loop  ;; label = @12
                            local.get 1
                            i32.load
                            local.tee 4
                            local.get 1
                            i32.load offset=4
                            local.tee 8
                            i32.add
                            local.get 0
                            i32.ne
                            if  ;; label = @13
                              local.get 1
                              i32.load offset=8
                              local.tee 1
                              br_if 1 (;@12;)
                              br 2 (;@11;)
                            end
                          end
                          local.get 2
                          local.get 4
                          i32.lt_u
                          local.get 0
                          local.get 2
                          i32.le_u
                          i32.or
                          br_if 0 (;@11;)
                          local.get 1
                          i32.load offset=12
                          local.tee 4
                          i32.const 1
                          i32.and
                          br_if 0 (;@11;)
                          local.get 4
                          i32.const 1
                          i32.shr_u
                          local.get 7
                          i32.eq
                          br_if 3 (;@8;)
                        end
                        i32.const 1050720
                        i32.const 1050720
                        i32.load
                        local.tee 1
                        local.get 0
                        local.get 0
                        local.get 1
                        i32.gt_u
                        select
                        i32.store
                        local.get 0
                        local.get 6
                        i32.add
                        local.set 4
                        i32.const 1050404
                        local.set 1
                        block  ;; label = @11
                          block  ;; label = @12
                            loop  ;; label = @13
                              local.get 4
                              local.get 1
                              i32.load
                              local.tee 8
                              i32.ne
                              if  ;; label = @14
                                local.get 1
                                i32.load offset=8
                                local.tee 1
                                br_if 1 (;@13;)
                                br 2 (;@12;)
                              end
                            end
                            local.get 1
                            i32.load offset=12
                            local.tee 4
                            i32.const 1
                            i32.and
                            br_if 0 (;@12;)
                            local.get 4
                            i32.const 1
                            i32.shr_u
                            local.get 7
                            i32.eq
                            br_if 1 (;@11;)
                          end
                          i32.const 1050404
                          local.set 1
                          loop  ;; label = @12
                            block  ;; label = @13
                              local.get 2
                              local.get 1
                              i32.load
                              local.tee 4
                              i32.ge_u
                              if  ;; label = @14
                                local.get 2
                                local.get 4
                                local.get 1
                                i32.load offset=4
                                i32.add
                                local.tee 8
                                i32.lt_u
                                br_if 1 (;@13;)
                              end
                              local.get 1
                              i32.load offset=8
                              local.set 1
                              br 1 (;@12;)
                            end
                          end
                          local.get 0
                          i32.const 15
                          i32.add
                          i32.const -8
                          i32.and
                          local.tee 1
                          i32.const 8
                          i32.sub
                          local.tee 4
                          local.get 6
                          i32.const 40
                          i32.sub
                          local.tee 10
                          local.get 0
                          local.get 1
                          i32.sub
                          i32.add
                          i32.const 8
                          i32.add
                          local.tee 1
                          i32.const 1
                          i32.or
                          i32.store offset=4
                          i32.const 1050716
                          i32.const 2097152
                          i32.store
                          i32.const 1050704
                          local.get 4
                          i32.store
                          i32.const 1050696
                          local.get 1
                          i32.store
                          local.get 0
                          local.get 10
                          i32.add
                          i32.const 40
                          i32.store offset=4
                          local.get 2
                          local.get 8
                          i32.const 32
                          i32.sub
                          i32.const -8
                          i32.and
                          i32.const 8
                          i32.sub
                          local.tee 1
                          local.get 1
                          local.get 2
                          i32.const 16
                          i32.add
                          i32.lt_u
                          select
                          local.tee 4
                          i32.const 27
                          i32.store offset=4
                          i32.const 1050404
                          i64.load align=4
                          local.set 11
                          local.get 4
                          i32.const 16
                          i32.add
                          i32.const 1050412
                          i64.load align=4
                          i64.store align=4
                          local.get 4
                          local.get 11
                          i64.store offset=8 align=4
                          i32.const 1050416
                          local.get 7
                          i32.store
                          i32.const 1050408
                          local.get 6
                          i32.store
                          i32.const 1050404
                          local.get 0
                          i32.store
                          i32.const 1050412
                          local.get 4
                          i32.const 8
                          i32.add
                          i32.store
                          local.get 4
                          i32.const 28
                          i32.add
                          local.set 1
                          loop  ;; label = @12
                            local.get 1
                            i32.const 7
                            i32.store
                            local.get 1
                            i32.const 4
                            i32.add
                            local.tee 1
                            local.get 8
                            i32.lt_u
                            br_if 0 (;@12;)
                          end
                          local.get 2
                          local.get 4
                          i32.eq
                          br_if 7 (;@4;)
                          local.get 4
                          local.get 4
                          i32.load offset=4
                          i32.const -2
                          i32.and
                          i32.store offset=4
                          local.get 2
                          local.get 4
                          local.get 2
                          i32.sub
                          local.tee 0
                          i32.const 1
                          i32.or
                          i32.store offset=4
                          local.get 4
                          local.get 0
                          i32.store
                          local.get 0
                          i32.const 256
                          i32.ge_u
                          if  ;; label = @12
                            local.get 2
                            local.get 0
                            call 11
                            br 8 (;@4;)
                          end
                          local.get 0
                          i32.const 248
                          i32.and
                          i32.const 1050420
                          i32.add
                          local.set 1
                          block (result i32)  ;; label = @12
                            i32.const 1050684
                            i32.load
                            local.tee 4
                            i32.const 1
                            local.get 0
                            i32.const 3
                            i32.shr_u
                            i32.shl
                            local.tee 0
                            i32.and
                            i32.eqz
                            if  ;; label = @13
                              i32.const 1050684
                              local.get 0
                              local.get 4
                              i32.or
                              i32.store
                              local.get 1
                              br 1 (;@12;)
                            end
                            local.get 1
                            i32.load offset=8
                          end
                          local.set 0
                          local.get 1
                          local.get 2
                          i32.store offset=8
                          local.get 0
                          local.get 2
                          i32.store offset=12
                          local.get 2
                          local.get 1
                          i32.store offset=12
                          local.get 2
                          local.get 0
                          i32.store offset=8
                          br 7 (;@4;)
                        end
                        local.get 1
                        local.get 0
                        i32.store
                        local.get 1
                        local.get 1
                        i32.load offset=4
                        local.get 6
                        i32.add
                        i32.store offset=4
                        local.get 0
                        i32.const 15
                        i32.add
                        i32.const -8
                        i32.and
                        i32.const 8
                        i32.sub
                        local.tee 3
                        local.get 5
                        i32.const 3
                        i32.or
                        i32.store offset=4
                        local.get 8
                        i32.const 15
                        i32.add
                        i32.const -8
                        i32.and
                        i32.const 8
                        i32.sub
                        local.tee 0
                        local.get 3
                        local.get 5
                        i32.add
                        local.tee 1
                        i32.sub
                        local.set 5
                        local.get 0
                        i32.const 1050704
                        i32.load
                        i32.eq
                        br_if 3 (;@7;)
                        local.get 0
                        i32.const 1050700
                        i32.load
                        i32.eq
                        br_if 4 (;@6;)
                        local.get 0
                        i32.load offset=4
                        local.tee 2
                        i32.const 3
                        i32.and
                        i32.const 1
                        i32.eq
                        if  ;; label = @11
                          local.get 0
                          local.get 2
                          i32.const -8
                          i32.and
                          local.tee 2
                          call 9
                          local.get 2
                          local.get 5
                          i32.add
                          local.set 5
                          local.get 0
                          local.get 2
                          i32.add
                          local.tee 0
                          i32.load offset=4
                          local.set 2
                        end
                        local.get 0
                        local.get 2
                        i32.const -2
                        i32.and
                        i32.store offset=4
                        local.get 1
                        local.get 5
                        i32.const 1
                        i32.or
                        i32.store offset=4
                        local.get 1
                        local.get 5
                        i32.add
                        local.get 5
                        i32.store
                        local.get 5
                        i32.const 256
                        i32.ge_u
                        if  ;; label = @11
                          local.get 1
                          local.get 5
                          call 11
                          br 6 (;@5;)
                        end
                        local.get 5
                        i32.const 248
                        i32.and
                        i32.const 1050420
                        i32.add
                        local.set 0
                        block (result i32)  ;; label = @11
                          i32.const 1050684
                          i32.load
                          local.tee 2
                          i32.const 1
                          local.get 5
                          i32.const 3
                          i32.shr_u
                          i32.shl
                          local.tee 4
                          i32.and
                          i32.eqz
                          if  ;; label = @12
                            i32.const 1050684
                            local.get 2
                            local.get 4
                            i32.or
                            i32.store
                            local.get 0
                            br 1 (;@11;)
                          end
                          local.get 0
                          i32.load offset=8
                        end
                        local.set 2
                        local.get 0
                        local.get 1
                        i32.store offset=8
                        local.get 2
                        local.get 1
                        i32.store offset=12
                        local.get 1
                        local.get 0
                        i32.store offset=12
                        local.get 1
                        local.get 2
                        i32.store offset=8
                        br 5 (;@5;)
                      end
                      i32.const 1050696
                      local.get 0
                      local.get 5
                      i32.sub
                      local.tee 1
                      i32.store
                      i32.const 1050704
                      i32.const 1050704
                      i32.load
                      local.tee 0
                      local.get 5
                      i32.add
                      local.tee 2
                      i32.store
                      local.get 2
                      local.get 1
                      i32.const 1
                      i32.or
                      i32.store offset=4
                      local.get 0
                      local.get 5
                      i32.const 3
                      i32.or
                      i32.store offset=4
                      local.get 0
                      i32.const 8
                      i32.add
                      local.set 3
                      br 8 (;@1;)
                    end
                    i32.const 1050700
                    i32.load
                    local.set 0
                    block  ;; label = @9
                      local.get 1
                      local.get 5
                      i32.sub
                      local.tee 2
                      i32.const 15
                      i32.le_u
                      if  ;; label = @10
                        i32.const 1050700
                        i32.const 0
                        i32.store
                        i32.const 1050692
                        i32.const 0
                        i32.store
                        local.get 0
                        local.get 1
                        i32.const 3
                        i32.or
                        i32.store offset=4
                        local.get 0
                        local.get 1
                        i32.add
                        local.tee 1
                        local.get 1
                        i32.load offset=4
                        i32.const 1
                        i32.or
                        i32.store offset=4
                        br 1 (;@9;)
                      end
                      i32.const 1050692
                      local.get 2
                      i32.store
                      i32.const 1050700
                      local.get 0
                      local.get 5
                      i32.add
                      local.tee 3
                      i32.store
                      local.get 3
                      local.get 2
                      i32.const 1
                      i32.or
                      i32.store offset=4
                      local.get 0
                      local.get 1
                      i32.add
                      local.get 2
                      i32.store
                      local.get 0
                      local.get 5
                      i32.const 3
                      i32.or
                      i32.store offset=4
                    end
                    local.get 0
                    i32.const 8
                    i32.add
                    local.set 3
                    br 7 (;@1;)
                  end
                  local.get 1
                  local.get 6
                  local.get 8
                  i32.add
                  i32.store offset=4
                  i32.const 1050704
                  i32.load
                  local.tee 0
                  i32.const 15
                  i32.add
                  i32.const -8
                  i32.and
                  local.tee 1
                  i32.const 8
                  i32.sub
                  local.tee 2
                  i32.const 1050696
                  i32.load
                  local.get 6
                  i32.add
                  local.tee 4
                  local.get 0
                  local.get 1
                  i32.sub
                  i32.add
                  i32.const 8
                  i32.add
                  local.tee 1
                  i32.const 1
                  i32.or
                  i32.store offset=4
                  i32.const 1050716
                  i32.const 2097152
                  i32.store
                  i32.const 1050704
                  local.get 2
                  i32.store
                  i32.const 1050696
                  local.get 1
                  i32.store
                  local.get 0
                  local.get 4
                  i32.add
                  i32.const 40
                  i32.store offset=4
                  br 3 (;@4;)
                end
                i32.const 1050704
                local.get 1
                i32.store
                i32.const 1050696
                i32.const 1050696
                i32.load
                local.get 5
                i32.add
                local.tee 0
                i32.store
                local.get 1
                local.get 0
                i32.const 1
                i32.or
                i32.store offset=4
                br 1 (;@5;)
              end
              local.get 1
              i32.const 1050692
              i32.load
              local.get 5
              i32.add
              local.tee 0
              i32.const 1
              i32.or
              i32.store offset=4
              i32.const 1050700
              local.get 1
              i32.store
              i32.const 1050692
              local.get 0
              i32.store
              local.get 0
              local.get 1
              i32.add
              local.get 0
              i32.store
            end
            local.get 3
            i32.const 8
            i32.add
            local.set 3
            br 3 (;@1;)
          end
          i32.const 1050696
          i32.load
          local.tee 0
          local.get 5
          i32.le_u
          br_if 2 (;@1;)
          i32.const 1050696
          local.get 0
          local.get 5
          i32.sub
          local.tee 1
          i32.store
          i32.const 1050704
          i32.const 1050704
          i32.load
          local.tee 0
          local.get 5
          i32.add
          local.tee 2
          i32.store
          local.get 2
          local.get 1
          i32.const 1
          i32.or
          i32.store offset=4
          local.get 0
          local.get 5
          i32.const 3
          i32.or
          i32.store offset=4
          local.get 0
          i32.const 8
          i32.add
          local.set 3
          br 2 (;@1;)
        end
        i32.const 1050688
        i32.const 1050688
        i32.load
        i32.const -2
        local.get 2
        i32.rotl
        i32.and
        i32.store
      end
      block  ;; label = @2
        local.get 0
        i32.const 16
        i32.ge_u
        if  ;; label = @3
          local.get 3
          local.get 5
          i32.const 3
          i32.or
          i32.store offset=4
          local.get 3
          local.get 5
          i32.add
          local.tee 1
          local.get 0
          i32.const 1
          i32.or
          i32.store offset=4
          local.get 0
          local.get 1
          i32.add
          local.get 0
          i32.store
          local.get 0
          i32.const 256
          i32.ge_u
          if  ;; label = @4
            local.get 1
            local.get 0
            call 11
            br 2 (;@2;)
          end
          local.get 0
          i32.const 248
          i32.and
          i32.const 1050420
          i32.add
          local.set 2
          block (result i32)  ;; label = @4
            i32.const 1050684
            i32.load
            local.tee 4
            i32.const 1
            local.get 0
            i32.const 3
            i32.shr_u
            i32.shl
            local.tee 0
            i32.and
            i32.eqz
            if  ;; label = @5
              i32.const 1050684
              local.get 0
              local.get 4
              i32.or
              i32.store
              local.get 2
              br 1 (;@4;)
            end
            local.get 2
            i32.load offset=8
          end
          local.set 0
          local.get 2
          local.get 1
          i32.store offset=8
          local.get 0
          local.get 1
          i32.store offset=12
          local.get 1
          local.get 2
          i32.store offset=12
          local.get 1
          local.get 0
          i32.store offset=8
          br 1 (;@2;)
        end
        local.get 3
        local.get 0
        local.get 5
        i32.add
        local.tee 0
        i32.const 3
        i32.or
        i32.store offset=4
        local.get 0
        local.get 3
        i32.add
        local.tee 0
        local.get 0
        i32.load offset=4
        i32.const 1
        i32.or
        i32.store offset=4
      end
      local.get 3
      i32.const 8
      i32.add
      local.set 3
    end
    local.get 9
    i32.const 16
    i32.add
    global.set 0
    local.get 3)
  (func (;2;) (type 3) (param i32)
    (local i32 i32 i32 i32 i32)
    local.get 0
    i32.const 8
    i32.sub
    local.tee 1
    local.get 0
    i32.const 4
    i32.sub
    i32.load
    local.tee 3
    i32.const -8
    i32.and
    local.tee 0
    i32.add
    local.set 2
    block  ;; label = @1
      block  ;; label = @2
        local.get 3
        i32.const 1
        i32.and
        br_if 0 (;@2;)
        local.get 3
        i32.const 2
        i32.and
        i32.eqz
        br_if 1 (;@1;)
        local.get 1
        i32.load
        local.tee 3
        local.get 0
        i32.add
        local.set 0
        local.get 1
        local.get 3
        i32.sub
        local.tee 1
        i32.const 1050700
        i32.load
        i32.eq
        if  ;; label = @3
          local.get 2
          i32.load offset=4
          local.tee 3
          i32.const 3
          i32.and
          i32.const 3
          i32.ne
          br_if 1 (;@2;)
          local.get 2
          local.get 3
          i32.const -2
          i32.and
          i32.store offset=4
          local.get 1
          local.get 0
          i32.const 1
          i32.or
          i32.store offset=4
          i32.const 1050692
          local.get 0
          i32.store
          local.get 2
          local.get 0
          i32.store
          return
        end
        local.get 1
        local.get 3
        call 9
      end
      block  ;; label = @2
        block  ;; label = @3
          block  ;; label = @4
            block  ;; label = @5
              block  ;; label = @6
                block  ;; label = @7
                  block  ;; label = @8
                    block  ;; label = @9
                      local.get 2
                      i32.load offset=4
                      local.tee 3
                      i32.const 2
                      i32.and
                      i32.eqz
                      if  ;; label = @10
                        local.get 2
                        i32.const 1050704
                        i32.load
                        i32.eq
                        br_if 2 (;@8;)
                        local.get 2
                        i32.const 1050700
                        i32.load
                        i32.eq
                        br_if 3 (;@7;)
                        local.get 2
                        local.get 3
                        i32.const -8
                        i32.and
                        local.tee 2
                        call 9
                        local.get 1
                        local.get 0
                        local.get 2
                        i32.add
                        local.tee 0
                        i32.const 1
                        i32.or
                        i32.store offset=4
                        local.get 0
                        local.get 1
                        i32.add
                        local.get 0
                        i32.store
                        local.get 1
                        i32.const 1050700
                        i32.load
                        i32.ne
                        br_if 1 (;@9;)
                        i32.const 1050692
                        local.get 0
                        i32.store
                        return
                      end
                      local.get 2
                      local.get 3
                      i32.const -2
                      i32.and
                      i32.store offset=4
                      local.get 1
                      local.get 0
                      i32.const 1
                      i32.or
                      i32.store offset=4
                      local.get 0
                      local.get 1
                      i32.add
                      local.get 0
                      i32.store
                    end
                    local.get 0
                    i32.const 256
                    i32.lt_u
                    br_if 2 (;@6;)
                    i32.const 31
                    local.set 2
                    local.get 1
                    i64.const 0
                    i64.store offset=16 align=4
                    local.get 0
                    i32.const 16777215
                    i32.le_u
                    if  ;; label = @9
                      local.get 0
                      i32.const 6
                      local.get 0
                      i32.const 8
                      i32.shr_u
                      i32.clz
                      local.tee 2
                      i32.sub
                      i32.shr_u
                      i32.const 1
                      i32.and
                      local.get 2
                      i32.const 1
                      i32.shl
                      i32.sub
                      i32.const 62
                      i32.add
                      local.set 2
                    end
                    local.get 1
                    local.get 2
                    i32.store offset=28
                    local.get 2
                    i32.const 2
                    i32.shl
                    i32.const 1050276
                    i32.add
                    local.set 3
                    i32.const 1
                    local.get 2
                    i32.shl
                    local.tee 4
                    i32.const 1050688
                    i32.load
                    i32.and
                    br_if 3 (;@5;)
                    local.get 3
                    local.get 1
                    i32.store
                    local.get 1
                    local.get 3
                    i32.store offset=24
                    i32.const 1050688
                    i32.const 1050688
                    i32.load
                    local.get 4
                    i32.or
                    i32.store
                    br 4 (;@4;)
                  end
                  i32.const 1050704
                  local.get 1
                  i32.store
                  i32.const 1050696
                  i32.const 1050696
                  i32.load
                  local.get 0
                  i32.add
                  local.tee 0
                  i32.store
                  local.get 1
                  local.get 0
                  i32.const 1
                  i32.or
                  i32.store offset=4
                  i32.const 1050700
                  i32.load
                  local.get 1
                  i32.eq
                  if  ;; label = @8
                    i32.const 1050692
                    i32.const 0
                    i32.store
                    i32.const 1050700
                    i32.const 0
                    i32.store
                  end
                  local.get 0
                  i32.const 1050716
                  i32.load
                  i32.le_u
                  br_if 6 (;@1;)
                  local.get 0
                  i32.const 41
                  i32.lt_u
                  br_if 5 (;@2;)
                  i32.const 1050404
                  local.set 0
                  loop  ;; label = @8
                    local.get 1
                    local.get 0
                    i32.load
                    local.tee 2
                    i32.ge_u
                    if  ;; label = @9
                      local.get 1
                      local.get 2
                      local.get 0
                      i32.load offset=4
                      i32.add
                      i32.lt_u
                      br_if 7 (;@2;)
                    end
                    local.get 0
                    i32.load offset=8
                    local.set 0
                    br 0 (;@8;)
                  end
                  unreachable
                end
                local.get 1
                i32.const 1050692
                i32.load
                local.get 0
                i32.add
                local.tee 0
                i32.const 1
                i32.or
                i32.store offset=4
                i32.const 1050700
                local.get 1
                i32.store
                i32.const 1050692
                local.get 0
                i32.store
                local.get 0
                local.get 1
                i32.add
                local.get 0
                i32.store
                return
              end
              local.get 0
              i32.const 248
              i32.and
              i32.const 1050420
              i32.add
              local.set 2
              block (result i32)  ;; label = @6
                i32.const 1050684
                i32.load
                local.tee 3
                i32.const 1
                local.get 0
                i32.const 3
                i32.shr_u
                i32.shl
                local.tee 0
                i32.and
                i32.eqz
                if  ;; label = @7
                  i32.const 1050684
                  local.get 0
                  local.get 3
                  i32.or
                  i32.store
                  local.get 2
                  br 1 (;@6;)
                end
                local.get 2
                i32.load offset=8
              end
              local.set 0
              local.get 2
              local.get 1
              i32.store offset=8
              local.get 0
              local.get 1
              i32.store offset=12
              local.get 1
              local.get 2
              i32.store offset=12
              local.get 1
              local.get 0
              i32.store offset=8
              return
            end
            block  ;; label = @5
              block  ;; label = @6
                local.get 0
                local.get 3
                i32.load
                local.tee 3
                i32.load offset=4
                i32.const -8
                i32.and
                i32.eq
                if  ;; label = @7
                  local.get 3
                  local.set 2
                  br 1 (;@6;)
                end
                local.get 0
                i32.const 25
                local.get 2
                i32.const 1
                i32.shr_u
                i32.sub
                i32.const 0
                local.get 2
                i32.const 31
                i32.ne
                select
                i32.shl
                local.set 4
                loop  ;; label = @7
                  local.get 3
                  local.get 4
                  i32.const 29
                  i32.shr_u
                  i32.const 4
                  i32.and
                  i32.add
                  local.tee 5
                  i32.load offset=16
                  local.tee 2
                  i32.eqz
                  br_if 2 (;@5;)
                  local.get 4
                  i32.const 1
                  i32.shl
                  local.set 4
                  local.get 2
                  local.set 3
                  local.get 2
                  i32.load offset=4
                  i32.const -8
                  i32.and
                  local.get 0
                  i32.ne
                  br_if 0 (;@7;)
                end
              end
              local.get 2
              i32.load offset=8
              local.tee 0
              local.get 1
              i32.store offset=12
              local.get 2
              local.get 1
              i32.store offset=8
              local.get 1
              i32.const 0
              i32.store offset=24
              local.get 1
              local.get 2
              i32.store offset=12
              local.get 1
              local.get 0
              i32.store offset=8
              br 2 (;@3;)
            end
            local.get 5
            i32.const 16
            i32.add
            local.get 1
            i32.store
            local.get 1
            local.get 3
            i32.store offset=24
          end
          local.get 1
          local.get 1
          i32.store offset=12
          local.get 1
          local.get 1
          i32.store offset=8
        end
        i32.const 1050724
        i32.const 1050724
        i32.load
        i32.const 1
        i32.sub
        local.tee 0
        i32.store
        local.get 0
        br_if 1 (;@1;)
        block  ;; label = @3
          i32.const 1050412
          i32.load
          local.tee 0
          i32.eqz
          if  ;; label = @4
            i32.const 0
            local.set 1
            br 1 (;@3;)
          end
          i32.const 0
          local.set 1
          loop  ;; label = @4
            local.get 1
            i32.const 1
            i32.add
            local.set 1
            local.get 0
            i32.load offset=8
            local.tee 0
            br_if 0 (;@4;)
          end
        end
        i32.const 1050724
        i32.const 4095
        local.get 1
        local.get 1
        i32.const 4095
        i32.le_u
        select
        i32.store
        return
      end
      block  ;; label = @2
        i32.const 1050412
        i32.load
        local.tee 0
        i32.eqz
        if  ;; label = @3
          i32.const 0
          local.set 1
          br 1 (;@2;)
        end
        i32.const 0
        local.set 1
        loop  ;; label = @3
          local.get 1
          i32.const 1
          i32.add
          local.set 1
          local.get 0
          i32.load offset=8
          local.tee 0
          br_if 0 (;@3;)
        end
      end
      i32.const 1050716
      i32.const -1
      i32.store
      i32.const 1050724
      i32.const 4095
      local.get 1
      local.get 1
      i32.const 4095
      i32.le_u
      select
      i32.store
    end)
  (func (;3;) (type 1) (param i32 i32)
    (local i32 i32 i32 i32)
    local.get 0
    local.get 1
    i32.add
    local.set 2
    block  ;; label = @1
      block  ;; label = @2
        block  ;; label = @3
          local.get 0
          i32.load offset=4
          local.tee 3
          i32.const 1
          i32.and
          br_if 0 (;@3;)
          local.get 3
          i32.const 2
          i32.and
          i32.eqz
          br_if 1 (;@2;)
          local.get 0
          i32.load
          local.tee 3
          local.get 1
          i32.add
          local.set 1
          local.get 0
          local.get 3
          i32.sub
          local.tee 0
          i32.const 1050700
          i32.load
          i32.eq
          if  ;; label = @4
            local.get 2
            i32.load offset=4
            local.tee 3
            i32.const 3
            i32.and
            i32.const 3
            i32.ne
            br_if 1 (;@3;)
            local.get 2
            local.get 3
            i32.const -2
            i32.and
            i32.store offset=4
            local.get 0
            local.get 1
            i32.const 1
            i32.or
            i32.store offset=4
            i32.const 1050692
            local.get 1
            i32.store
            local.get 2
            local.get 1
            i32.store
            br 2 (;@2;)
          end
          local.get 0
          local.get 3
          call 9
        end
        block  ;; label = @3
          block  ;; label = @4
            block  ;; label = @5
              local.get 2
              i32.load offset=4
              local.tee 3
              i32.const 2
              i32.and
              i32.eqz
              if  ;; label = @6
                local.get 2
                i32.const 1050704
                i32.load
                i32.eq
                br_if 2 (;@4;)
                local.get 2
                i32.const 1050700
                i32.load
                i32.eq
                br_if 3 (;@3;)
                local.get 2
                local.get 3
                i32.const -8
                i32.and
                local.tee 2
                call 9
                local.get 0
                local.get 1
                local.get 2
                i32.add
                local.tee 1
                i32.const 1
                i32.or
                i32.store offset=4
                local.get 0
                local.get 1
                i32.add
                local.get 1
                i32.store
                local.get 0
                i32.const 1050700
                i32.load
                i32.ne
                br_if 1 (;@5;)
                i32.const 1050692
                local.get 1
                i32.store
                return
              end
              local.get 2
              local.get 3
              i32.const -2
              i32.and
              i32.store offset=4
              local.get 0
              local.get 1
              i32.const 1
              i32.or
              i32.store offset=4
              local.get 0
              local.get 1
              i32.add
              local.get 1
              i32.store
            end
            local.get 1
            i32.const 256
            i32.ge_u
            if  ;; label = @5
              i32.const 31
              local.set 4
              local.get 0
              i64.const 0
              i64.store offset=16 align=4
              local.get 1
              i32.const 16777215
              i32.le_u
              if  ;; label = @6
                local.get 1
                i32.const 6
                local.get 1
                i32.const 8
                i32.shr_u
                i32.clz
                local.tee 2
                i32.sub
                i32.shr_u
                i32.const 1
                i32.and
                local.get 2
                i32.const 1
                i32.shl
                i32.sub
                i32.const 62
                i32.add
                local.set 4
              end
              local.get 0
              local.get 4
              i32.store offset=28
              local.get 4
              i32.const 2
              i32.shl
              i32.const 1050276
              i32.add
              local.set 2
              block  ;; label = @6
                i32.const 1
                local.get 4
                i32.shl
                local.tee 3
                i32.const 1050688
                i32.load
                i32.and
                i32.eqz
                if  ;; label = @7
                  local.get 2
                  local.get 0
                  i32.store
                  local.get 0
                  local.get 2
                  i32.store offset=24
                  i32.const 1050688
                  i32.const 1050688
                  i32.load
                  local.get 3
                  i32.or
                  i32.store
                  br 1 (;@6;)
                end
                block  ;; label = @7
                  block  ;; label = @8
                    local.get 1
                    local.get 2
                    i32.load
                    local.tee 3
                    i32.load offset=4
                    i32.const -8
                    i32.and
                    i32.eq
                    if  ;; label = @9
                      local.get 3
                      local.set 2
                      br 1 (;@8;)
                    end
                    local.get 1
                    i32.const 25
                    local.get 4
                    i32.const 1
                    i32.shr_u
                    i32.sub
                    i32.const 0
                    local.get 4
                    i32.const 31
                    i32.ne
                    select
                    i32.shl
                    local.set 4
                    loop  ;; label = @9
                      local.get 3
                      local.get 4
                      i32.const 29
                      i32.shr_u
                      i32.const 4
                      i32.and
                      i32.add
                      local.tee 5
                      i32.load offset=16
                      local.tee 2
                      i32.eqz
                      br_if 2 (;@7;)
                      local.get 4
                      i32.const 1
                      i32.shl
                      local.set 4
                      local.get 2
                      local.set 3
                      local.get 2
                      i32.load offset=4
                      i32.const -8
                      i32.and
                      local.get 1
                      i32.ne
                      br_if 0 (;@9;)
                    end
                  end
                  local.get 2
                  i32.load offset=8
                  local.tee 1
                  local.get 0
                  i32.store offset=12
                  local.get 2
                  local.get 0
                  i32.store offset=8
                  local.get 0
                  i32.const 0
                  i32.store offset=24
                  br 6 (;@1;)
                end
                local.get 5
                i32.const 16
                i32.add
                local.get 0
                i32.store
                local.get 0
                local.get 3
                i32.store offset=24
              end
              local.get 0
              local.get 0
              i32.store offset=12
              local.get 0
              local.get 0
              i32.store offset=8
              return
            end
            local.get 1
            i32.const 248
            i32.and
            i32.const 1050420
            i32.add
            local.set 2
            block (result i32)  ;; label = @5
              i32.const 1050684
              i32.load
              local.tee 3
              i32.const 1
              local.get 1
              i32.const 3
              i32.shr_u
              i32.shl
              local.tee 1
              i32.and
              i32.eqz
              if  ;; label = @6
                i32.const 1050684
                local.get 1
                local.get 3
                i32.or
                i32.store
                local.get 2
                br 1 (;@5;)
              end
              local.get 2
              i32.load offset=8
            end
            local.set 1
            local.get 2
            local.get 0
            i32.store offset=8
            local.get 1
            local.get 0
            i32.store offset=12
            br 3 (;@1;)
          end
          i32.const 1050704
          local.get 0
          i32.store
          i32.const 1050696
          i32.const 1050696
          i32.load
          local.get 1
          i32.add
          local.tee 1
          i32.store
          local.get 0
          local.get 1
          i32.const 1
          i32.or
          i32.store offset=4
          local.get 0
          i32.const 1050700
          i32.load
          i32.ne
          br_if 1 (;@2;)
          i32.const 1050692
          i32.const 0
          i32.store
          i32.const 1050700
          i32.const 0
          i32.store
          return
        end
        local.get 0
        i32.const 1050692
        i32.load
        local.get 1
        i32.add
        local.tee 1
        i32.const 1
        i32.or
        i32.store offset=4
        i32.const 1050700
        local.get 0
        i32.store
        i32.const 1050692
        local.get 1
        i32.store
        local.get 0
        local.get 1
        i32.add
        local.get 1
        i32.store
      end
      return
    end
    local.get 0
    local.get 2
    i32.store offset=12
    local.get 0
    local.get 1
    i32.store offset=8)
  (func (;4;) (type 3) (param i32)
    (local i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32)
    local.get 0
    local.get 0
    i32.load offset=28
    local.tee 1
    local.get 0
    i32.load offset=4
    local.tee 4
    i32.xor
    local.tee 7
    local.get 0
    i32.load offset=16
    local.tee 5
    local.get 0
    i32.load offset=8
    local.tee 10
    i32.xor
    local.tee 12
    i32.xor
    local.tee 17
    local.get 0
    i32.load offset=12
    i32.xor
    local.tee 8
    local.get 0
    i32.load offset=24
    local.tee 6
    i32.xor
    local.tee 11
    local.get 1
    local.get 5
    i32.xor
    local.tee 18
    i32.xor
    local.tee 9
    local.get 6
    local.get 0
    i32.load offset=20
    i32.xor
    local.tee 2
    i32.xor
    local.tee 3
    local.get 4
    local.get 2
    local.get 0
    i32.load
    local.tee 4
    i32.xor
    local.tee 6
    i32.xor
    local.tee 19
    local.get 6
    i32.and
    i32.xor
    local.get 3
    local.get 7
    i32.and
    local.tee 13
    i32.xor
    local.get 7
    i32.xor
    local.get 9
    local.get 18
    i32.and
    local.tee 14
    local.get 2
    local.get 8
    local.get 10
    i32.xor
    local.tee 2
    i32.xor
    local.tee 8
    local.get 9
    i32.xor
    local.tee 23
    local.get 12
    i32.and
    i32.xor
    local.tee 15
    i32.xor
    local.tee 16
    local.get 15
    local.get 2
    local.get 17
    i32.and
    local.tee 15
    local.get 11
    local.get 2
    local.get 4
    i32.xor
    local.tee 24
    local.get 19
    local.get 1
    local.get 10
    i32.xor
    local.tee 10
    i32.xor
    local.tee 25
    i32.and
    i32.xor
    i32.xor
    i32.xor
    local.tee 20
    i32.and
    local.tee 11
    local.get 8
    local.get 10
    i32.and
    local.get 14
    i32.xor
    local.tee 14
    local.get 15
    local.get 5
    local.get 6
    i32.xor
    local.tee 15
    local.get 4
    i32.and
    local.get 10
    i32.xor
    local.get 8
    i32.xor
    i32.xor
    i32.xor
    local.tee 5
    i32.xor
    local.get 14
    local.get 13
    local.get 3
    local.get 4
    local.get 9
    i32.xor
    local.tee 13
    local.get 1
    local.get 6
    i32.xor
    local.tee 14
    i32.and
    i32.xor
    i32.xor
    local.get 1
    i32.xor
    i32.xor
    local.tee 1
    local.get 16
    i32.xor
    i32.and
    local.tee 21
    local.get 11
    i32.xor
    local.get 1
    i32.and
    local.tee 22
    local.get 16
    i32.xor
    local.tee 16
    local.get 2
    i32.and
    local.tee 26
    local.get 4
    local.get 1
    local.get 21
    i32.xor
    local.tee 4
    i32.and
    i32.xor
    local.tee 21
    local.get 5
    local.get 1
    local.get 11
    i32.xor
    local.tee 2
    local.get 5
    local.get 20
    i32.xor
    local.tee 5
    i32.and
    i32.xor
    local.tee 1
    local.get 13
    i32.and
    i32.xor
    local.get 3
    local.get 2
    local.get 22
    i32.xor
    local.get 1
    i32.and
    local.get 5
    i32.xor
    local.tee 3
    local.get 1
    i32.xor
    local.tee 11
    i32.and
    local.tee 13
    i32.xor
    local.tee 20
    local.get 3
    local.get 19
    i32.and
    i32.xor
    local.get 12
    local.get 3
    local.get 4
    local.get 16
    i32.xor
    local.tee 2
    i32.xor
    local.tee 5
    local.get 1
    local.get 4
    i32.xor
    local.tee 12
    i32.xor
    local.tee 19
    i32.and
    local.get 12
    local.get 18
    i32.and
    local.tee 18
    i32.xor
    local.tee 22
    i32.xor
    local.tee 27
    local.get 13
    local.get 3
    local.get 6
    i32.and
    i32.xor
    local.tee 6
    local.get 19
    local.get 23
    i32.and
    i32.xor
    local.tee 3
    local.get 7
    local.get 11
    i32.and
    local.tee 7
    local.get 5
    local.get 8
    i32.and
    local.get 21
    i32.xor
    i32.xor
    i32.xor
    local.tee 8
    i32.xor
    i32.store offset=4
    local.get 0
    local.get 7
    local.get 27
    i32.xor
    i32.store
    local.get 0
    local.get 22
    local.get 2
    local.get 25
    i32.and
    i32.xor
    local.tee 7
    local.get 16
    local.get 17
    i32.and
    i32.xor
    local.tee 17
    local.get 3
    local.get 9
    local.get 12
    i32.and
    i32.xor
    local.tee 9
    i32.xor
    i32.store offset=28
    local.get 0
    local.get 8
    local.get 1
    local.get 14
    i32.and
    i32.xor
    local.tee 3
    local.get 5
    local.get 10
    i32.and
    local.get 18
    i32.xor
    local.get 9
    i32.xor
    i32.xor
    i32.store offset=20
    local.get 0
    local.get 2
    local.get 24
    i32.and
    local.get 26
    i32.xor
    local.get 6
    i32.xor
    local.get 17
    i32.xor
    local.tee 1
    i32.store offset=16
    local.get 0
    local.get 7
    local.get 4
    local.get 15
    i32.and
    i32.xor
    local.get 3
    i32.xor
    i32.store offset=8
    local.get 0
    local.get 1
    local.get 9
    i32.xor
    i32.store offset=24
    local.get 0
    local.get 1
    local.get 20
    i32.xor
    i32.store offset=12)
  (func (;5;) (type 2) (param i32 i32 i32) (result i32)
    (local i32 i32 i32 i32 i32 i32 i32 i32)
    global.get 0
    i32.const 16
    i32.sub
    local.tee 3
    global.set 0
    local.get 3
    local.get 1
    i32.store offset=4
    local.get 3
    local.get 0
    i32.store
    local.get 3
    i64.const 3758096416
    i64.store offset=8 align=4
    block (result i32)  ;; label = @1
      block  ;; label = @2
        block  ;; label = @3
          block  ;; label = @4
            local.get 2
            i32.load offset=16
            local.tee 9
            if  ;; label = @5
              local.get 2
              i32.load offset=20
              local.tee 0
              br_if 1 (;@4;)
              br 2 (;@3;)
            end
            local.get 2
            i32.load offset=12
            local.tee 0
            i32.eqz
            br_if 1 (;@3;)
            local.get 2
            i32.load offset=8
            local.tee 1
            local.get 0
            i32.const 3
            i32.shl
            i32.add
            local.set 4
            local.get 0
            i32.const 1
            i32.sub
            i32.const 536870911
            i32.and
            i32.const 1
            i32.add
            local.set 6
            local.get 2
            i32.load
            local.set 0
            loop  ;; label = @5
              block  ;; label = @6
                local.get 0
                i32.const 4
                i32.add
                i32.load
                local.tee 5
                i32.eqz
                br_if 0 (;@6;)
                local.get 3
                i32.load
                local.get 0
                i32.load
                local.get 5
                local.get 3
                i32.load offset=4
                i32.load offset=12
                call_indirect (type 2)
                i32.eqz
                br_if 0 (;@6;)
                i32.const 1
                br 5 (;@1;)
              end
              i32.const 1
              local.get 1
              i32.load
              local.get 3
              local.get 1
              i32.const 4
              i32.add
              i32.load
              call_indirect (type 0)
              br_if 4 (;@1;)
              drop
              local.get 0
              i32.const 8
              i32.add
              local.set 0
              local.get 4
              local.get 1
              i32.const 8
              i32.add
              local.tee 1
              i32.ne
              br_if 0 (;@5;)
            end
            br 2 (;@2;)
          end
          local.get 0
          i32.const 24
          i32.mul
          local.set 10
          local.get 0
          i32.const 1
          i32.sub
          i32.const 536870911
          i32.and
          i32.const 1
          i32.add
          local.set 6
          local.get 2
          i32.load offset=8
          local.set 4
          local.get 2
          i32.load
          local.set 0
          loop  ;; label = @4
            block  ;; label = @5
              local.get 0
              i32.const 4
              i32.add
              i32.load
              local.tee 1
              i32.eqz
              br_if 0 (;@5;)
              local.get 3
              i32.load
              local.get 0
              i32.load
              local.get 1
              local.get 3
              i32.load offset=4
              i32.load offset=12
              call_indirect (type 2)
              i32.eqz
              br_if 0 (;@5;)
              i32.const 1
              br 4 (;@1;)
            end
            i32.const 0
            local.set 7
            i32.const 0
            local.set 8
            block  ;; label = @5
              block  ;; label = @6
                block  ;; label = @7
                  local.get 5
                  local.get 9
                  i32.add
                  local.tee 1
                  i32.const 8
                  i32.add
                  i32.load16_u
                  i32.const 1
                  i32.sub
                  br_table 1 (;@6;) 2 (;@5;) 0 (;@7;)
                end
                local.get 1
                i32.const 10
                i32.add
                i32.load16_u
                local.set 8
                br 1 (;@5;)
              end
              local.get 4
              local.get 1
              i32.const 12
              i32.add
              i32.load
              i32.const 3
              i32.shl
              i32.add
              i32.load16_u offset=4
              local.set 8
            end
            block  ;; label = @5
              block  ;; label = @6
                block  ;; label = @7
                  local.get 1
                  i32.load16_u
                  i32.const 1
                  i32.sub
                  br_table 1 (;@6;) 2 (;@5;) 0 (;@7;)
                end
                local.get 1
                i32.const 2
                i32.add
                i32.load16_u
                local.set 7
                br 1 (;@5;)
              end
              local.get 4
              local.get 1
              i32.const 4
              i32.add
              i32.load
              i32.const 3
              i32.shl
              i32.add
              i32.load16_u offset=4
              local.set 7
            end
            local.get 3
            local.get 7
            i32.store16 offset=14
            local.get 3
            local.get 8
            i32.store16 offset=12
            local.get 3
            local.get 1
            i32.const 20
            i32.add
            i32.load
            i32.store offset=8
            i32.const 1
            local.get 4
            local.get 1
            i32.const 16
            i32.add
            i32.load
            i32.const 3
            i32.shl
            i32.add
            local.tee 1
            i32.load
            local.get 3
            local.get 1
            i32.const 4
            i32.add
            i32.load
            call_indirect (type 0)
            br_if 3 (;@1;)
            drop
            local.get 0
            i32.const 8
            i32.add
            local.set 0
            local.get 5
            i32.const 24
            i32.add
            local.tee 5
            local.get 10
            i32.ne
            br_if 0 (;@4;)
          end
          br 1 (;@2;)
        end
      end
      block  ;; label = @2
        local.get 6
        local.get 2
        i32.load offset=4
        i32.ge_u
        br_if 0 (;@2;)
        local.get 3
        i32.load
        local.get 2
        i32.load
        local.get 6
        i32.const 3
        i32.shl
        i32.add
        local.tee 0
        i32.load
        local.get 0
        i32.load offset=4
        local.get 3
        i32.load offset=4
        i32.load offset=12
        call_indirect (type 2)
        i32.eqz
        br_if 0 (;@2;)
        i32.const 1
        br 1 (;@1;)
      end
      i32.const 0
    end
    local.get 3
    i32.const 16
    i32.add
    global.set 0)
  (func (;6;) (type 4) (param i32 i32 i32)
    (local i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32)
    global.get 0
    i32.const 32
    i32.sub
    local.tee 3
    global.set 0
    local.get 3
    local.get 2
    local.get 2
    i32.const 16
    i32.add
    call 7
    i32.const 0
    local.set 2
    loop  ;; label = @1
      local.get 2
      local.get 3
      i32.add
      local.tee 9
      local.get 9
      i32.load
      local.get 1
      local.get 2
      i32.add
      i32.load
      i32.xor
      i32.store
      local.get 2
      i32.const 4
      i32.add
      local.tee 2
      i32.const 32
      i32.ne
      br_if 0 (;@1;)
    end
    local.get 1
    i32.const 128
    i32.add
    local.set 9
    local.get 1
    i32.const 32
    i32.add
    local.set 12
    local.get 1
    i32.const 96
    i32.add
    local.set 13
    local.get 1
    i32.const -64
    i32.sub
    local.set 15
    i32.const 8
    local.set 16
    loop  ;; label = @1
      local.get 3
      call 4
      local.get 3
      local.get 3
      i32.load offset=24
      local.tee 2
      i32.const 22
      i32.rotl
      i32.const 1061109567
      i32.and
      local.get 2
      i32.const 30
      i32.rotl
      i32.const -1061109568
      i32.and
      i32.or
      local.tee 6
      local.get 2
      i32.xor
      local.tee 4
      local.get 3
      i32.load offset=28
      local.tee 2
      i32.const 22
      i32.rotl
      i32.const 1061109567
      i32.and
      local.get 2
      i32.const 30
      i32.rotl
      i32.const -1061109568
      i32.and
      i32.or
      local.tee 5
      local.get 2
      i32.xor
      local.tee 2
      i32.const 12
      i32.rotl
      i32.const 252645135
      i32.and
      local.get 2
      i32.const 20
      i32.rotl
      i32.const -252645136
      i32.and
      i32.or
      i32.xor
      local.get 5
      i32.xor
      i32.store offset=28
      local.get 3
      local.get 6
      local.get 3
      i32.load offset=20
      local.tee 5
      i32.const 22
      i32.rotl
      i32.const 1061109567
      i32.and
      local.get 5
      i32.const 30
      i32.rotl
      i32.const -1061109568
      i32.and
      i32.or
      local.tee 7
      local.get 5
      i32.xor
      local.tee 5
      local.get 4
      i32.const 12
      i32.rotl
      i32.const 252645135
      i32.and
      local.get 4
      i32.const 20
      i32.rotl
      i32.const -252645136
      i32.and
      i32.or
      i32.xor
      i32.xor
      i32.store offset=24
      local.get 3
      local.get 3
      i32.load offset=16
      local.tee 4
      i32.const 22
      i32.rotl
      i32.const 1061109567
      i32.and
      local.get 4
      i32.const 30
      i32.rotl
      i32.const -1061109568
      i32.and
      i32.or
      local.tee 10
      local.get 4
      i32.xor
      local.tee 4
      local.get 5
      i32.const 12
      i32.rotl
      i32.const 252645135
      i32.and
      local.get 5
      i32.const 20
      i32.rotl
      i32.const -252645136
      i32.and
      i32.or
      i32.xor
      local.get 7
      i32.xor
      i32.store offset=20
      local.get 3
      local.get 3
      i32.load offset=4
      local.tee 5
      i32.const 22
      i32.rotl
      i32.const 1061109567
      i32.and
      local.get 5
      i32.const 30
      i32.rotl
      i32.const -1061109568
      i32.and
      i32.or
      local.tee 11
      local.get 5
      i32.xor
      local.tee 5
      local.get 3
      i32.load offset=8
      local.tee 6
      i32.const 22
      i32.rotl
      i32.const 1061109567
      i32.and
      local.get 6
      i32.const 30
      i32.rotl
      i32.const -1061109568
      i32.and
      i32.or
      local.tee 7
      local.get 6
      i32.xor
      local.tee 6
      i32.const 12
      i32.rotl
      i32.const 252645135
      i32.and
      local.get 6
      i32.const 20
      i32.rotl
      i32.const -252645136
      i32.and
      i32.or
      i32.xor
      local.get 7
      i32.xor
      i32.store offset=8
      local.get 3
      local.get 3
      i32.load
      local.tee 7
      i32.const 22
      i32.rotl
      i32.const 1061109567
      i32.and
      local.get 7
      i32.const 30
      i32.rotl
      i32.const -1061109568
      i32.and
      i32.or
      local.tee 8
      local.get 7
      i32.xor
      local.tee 7
      i32.const 12
      i32.rotl
      i32.const 252645135
      i32.and
      local.get 7
      i32.const 20
      i32.rotl
      i32.const -252645136
      i32.and
      i32.or
      local.get 8
      i32.xor
      local.get 2
      i32.xor
      i32.store
      local.get 3
      local.get 10
      local.get 3
      i32.load offset=12
      local.tee 8
      i32.const 22
      i32.rotl
      i32.const 1061109567
      i32.and
      local.get 8
      i32.const 30
      i32.rotl
      i32.const -1061109568
      i32.and
      i32.or
      local.tee 14
      local.get 8
      i32.xor
      local.tee 8
      local.get 4
      i32.const 12
      i32.rotl
      i32.const 252645135
      i32.and
      local.get 4
      i32.const 20
      i32.rotl
      i32.const -252645136
      i32.and
      i32.or
      i32.xor
      i32.xor
      local.get 2
      i32.xor
      i32.store offset=16
      local.get 3
      local.get 6
      local.get 8
      i32.const 12
      i32.rotl
      i32.const 252645135
      i32.and
      local.get 8
      i32.const 20
      i32.rotl
      i32.const -252645136
      i32.and
      i32.or
      i32.xor
      local.get 14
      i32.xor
      local.get 2
      i32.xor
      i32.store offset=12
      local.get 3
      local.get 7
      local.get 5
      i32.const 12
      i32.rotl
      i32.const 252645135
      i32.and
      local.get 5
      i32.const 20
      i32.rotl
      i32.const -252645136
      i32.and
      i32.or
      i32.xor
      local.get 11
      i32.xor
      local.get 2
      i32.xor
      i32.store offset=4
      i32.const 0
      local.set 2
      loop  ;; label = @2
        local.get 2
        local.get 3
        i32.add
        local.tee 4
        local.get 4
        i32.load
        local.get 2
        local.get 12
        i32.add
        i32.load
        i32.xor
        i32.store
        local.get 2
        i32.const 4
        i32.add
        local.tee 2
        i32.const 32
        i32.ne
        br_if 0 (;@2;)
      end
      local.get 16
      i32.const 72
      i32.eq
      if  ;; label = @2
        i32.const 0
        local.set 2
        loop  ;; label = @3
          local.get 2
          local.get 3
          i32.add
          local.tee 9
          local.get 9
          i32.load
          local.tee 9
          local.get 9
          local.get 9
          i32.const 4
          i32.shr_u
          i32.xor
          i32.const 251662080
          i32.and
          local.tee 9
          i32.const 4
          i32.shl
          i32.xor
          local.get 9
          i32.xor
          i32.store
          local.get 2
          i32.const 4
          i32.add
          local.tee 2
          i32.const 32
          i32.ne
          br_if 0 (;@3;)
        end
        local.get 1
        i32.const 320
        i32.add
        local.set 1
        local.get 3
        call 4
        i32.const 0
        local.set 2
        loop  ;; label = @3
          local.get 2
          local.get 3
          i32.add
          local.tee 9
          local.get 9
          i32.load
          local.get 1
          local.get 2
          i32.add
          i32.load
          i32.xor
          i32.store
          local.get 2
          i32.const 4
          i32.add
          local.tee 2
          i32.const 32
          i32.ne
          br_if 0 (;@3;)
        end
        local.get 0
        local.get 3
        i32.load offset=28
        local.tee 1
        local.get 3
        i32.load offset=24
        local.tee 2
        i32.const 1
        i32.shr_u
        i32.xor
        i32.const 1431655765
        i32.and
        local.tee 9
        local.get 1
        i32.xor
        local.tee 1
        local.get 3
        i32.load offset=20
        local.tee 12
        local.get 3
        i32.load offset=16
        local.tee 13
        i32.const 1
        i32.shr_u
        i32.xor
        i32.const 1431655765
        i32.and
        local.tee 15
        local.get 12
        i32.xor
        local.tee 12
        i32.const 2
        i32.shr_u
        i32.xor
        i32.const 858993459
        i32.and
        local.tee 16
        local.get 1
        i32.xor
        local.tee 1
        local.get 3
        i32.load offset=12
        local.tee 4
        local.get 3
        i32.load offset=8
        local.tee 5
        i32.const 1
        i32.shr_u
        i32.xor
        i32.const 1431655765
        i32.and
        local.tee 6
        local.get 4
        i32.xor
        local.tee 4
        local.get 3
        i32.load offset=4
        local.tee 7
        local.get 3
        i32.load
        local.tee 8
        i32.const 1
        i32.shr_u
        i32.xor
        i32.const 1431655765
        i32.and
        local.tee 10
        local.get 7
        i32.xor
        local.tee 7
        i32.const 2
        i32.shr_u
        i32.xor
        i32.const 858993459
        i32.and
        local.tee 11
        local.get 4
        i32.xor
        local.tee 4
        i32.const 4
        i32.shr_u
        i32.xor
        i32.const 252645135
        i32.and
        local.tee 14
        local.get 1
        i32.xor
        i32.store offset=28 align=1
        local.get 0
        local.get 16
        i32.const 2
        i32.shl
        local.get 12
        i32.xor
        local.tee 1
        local.get 11
        i32.const 2
        i32.shl
        local.get 7
        i32.xor
        local.tee 12
        i32.const 4
        i32.shr_u
        i32.xor
        i32.const 252645135
        i32.and
        local.tee 16
        local.get 1
        i32.xor
        i32.store offset=24 align=1
        local.get 0
        local.get 14
        i32.const 4
        i32.shl
        local.get 4
        i32.xor
        i32.store offset=20 align=1
        local.get 0
        local.get 2
        local.get 9
        i32.const 1
        i32.shl
        i32.xor
        local.tee 1
        local.get 13
        local.get 15
        i32.const 1
        i32.shl
        i32.xor
        local.tee 2
        i32.const 2
        i32.shr_u
        i32.xor
        i32.const 858993459
        i32.and
        local.tee 9
        local.get 1
        i32.xor
        local.tee 1
        local.get 5
        local.get 6
        i32.const 1
        i32.shl
        i32.xor
        local.tee 13
        local.get 8
        local.get 10
        i32.const 1
        i32.shl
        i32.xor
        local.tee 15
        i32.const 2
        i32.shr_u
        i32.xor
        i32.const 858993459
        i32.and
        local.tee 4
        local.get 13
        i32.xor
        local.tee 13
        i32.const 4
        i32.shr_u
        i32.xor
        i32.const 252645135
        i32.and
        local.tee 5
        local.get 1
        i32.xor
        i32.store offset=12 align=1
        local.get 0
        local.get 16
        i32.const 4
        i32.shl
        local.get 12
        i32.xor
        i32.store offset=16 align=1
        local.get 0
        local.get 9
        i32.const 2
        i32.shl
        local.get 2
        i32.xor
        local.tee 1
        local.get 4
        i32.const 2
        i32.shl
        local.get 15
        i32.xor
        local.tee 2
        i32.const 4
        i32.shr_u
        i32.xor
        i32.const 252645135
        i32.and
        local.tee 9
        local.get 1
        i32.xor
        i32.store offset=8 align=1
        local.get 0
        local.get 5
        i32.const 4
        i32.shl
        local.get 13
        i32.xor
        i32.store offset=4 align=1
        local.get 0
        local.get 9
        i32.const 4
        i32.shl
        local.get 2
        i32.xor
        i32.store align=1
        local.get 3
        i32.const 32
        i32.add
        global.set 0
      else
        local.get 3
        call 4
        local.get 3
        local.get 3
        i32.load offset=24
        local.tee 2
        i32.const 20
        i32.rotl
        i32.const 252645135
        i32.and
        local.get 2
        i32.const 28
        i32.rotl
        i32.const -252645136
        i32.and
        i32.or
        local.tee 5
        local.get 2
        i32.xor
        local.tee 6
        local.get 3
        i32.load offset=28
        local.tee 2
        i32.const 20
        i32.rotl
        i32.const 252645135
        i32.and
        local.get 2
        i32.const 28
        i32.rotl
        i32.const -252645136
        i32.and
        i32.or
        local.tee 4
        local.get 2
        i32.xor
        local.tee 2
        i32.const 16
        i32.rotl
        i32.xor
        local.get 4
        i32.xor
        i32.store offset=28
        local.get 3
        local.get 5
        local.get 3
        i32.load offset=20
        local.tee 4
        i32.const 20
        i32.rotl
        i32.const 252645135
        i32.and
        local.get 4
        i32.const 28
        i32.rotl
        i32.const -252645136
        i32.and
        i32.or
        local.tee 7
        local.get 4
        i32.xor
        local.tee 8
        local.get 6
        i32.const 16
        i32.rotl
        i32.xor
        i32.xor
        i32.store offset=24
        local.get 3
        local.get 7
        local.get 3
        i32.load offset=16
        local.tee 4
        i32.const 20
        i32.rotl
        i32.const 252645135
        i32.and
        local.get 4
        i32.const 28
        i32.rotl
        i32.const -252645136
        i32.and
        i32.or
        local.tee 5
        local.get 4
        i32.xor
        local.tee 6
        local.get 8
        i32.const 16
        i32.rotl
        i32.xor
        i32.xor
        i32.store offset=20
        local.get 3
        local.get 3
        i32.load offset=4
        local.tee 4
        i32.const 20
        i32.rotl
        i32.const 252645135
        i32.and
        local.get 4
        i32.const 28
        i32.rotl
        i32.const -252645136
        i32.and
        i32.or
        local.tee 7
        local.get 4
        i32.xor
        local.tee 8
        local.get 3
        i32.load offset=8
        local.tee 4
        i32.const 20
        i32.rotl
        i32.const 252645135
        i32.and
        local.get 4
        i32.const 28
        i32.rotl
        i32.const -252645136
        i32.and
        i32.or
        local.tee 10
        local.get 4
        i32.xor
        local.tee 11
        i32.const 16
        i32.rotl
        i32.xor
        local.get 10
        i32.xor
        i32.store offset=8
        local.get 3
        local.get 3
        i32.load
        local.tee 4
        i32.const 20
        i32.rotl
        i32.const 252645135
        i32.and
        local.get 4
        i32.const 28
        i32.rotl
        i32.const -252645136
        i32.and
        i32.or
        local.tee 10
        local.get 4
        i32.xor
        local.tee 14
        i32.const 16
        i32.rotl
        local.get 10
        i32.xor
        local.get 2
        i32.xor
        i32.store
        local.get 3
        local.get 5
        local.get 3
        i32.load offset=12
        local.tee 4
        i32.const 20
        i32.rotl
        i32.const 252645135
        i32.and
        local.get 4
        i32.const 28
        i32.rotl
        i32.const -252645136
        i32.and
        i32.or
        local.tee 10
        local.get 4
        i32.xor
        local.tee 4
        local.get 6
        i32.const 16
        i32.rotl
        i32.xor
        i32.xor
        local.get 2
        i32.xor
        i32.store offset=16
        local.get 3
        local.get 11
        local.get 4
        i32.const 16
        i32.rotl
        i32.xor
        local.get 10
        i32.xor
        local.get 2
        i32.xor
        i32.store offset=12
        local.get 3
        local.get 14
        local.get 8
        i32.const 16
        i32.rotl
        i32.xor
        local.get 7
        i32.xor
        local.get 2
        i32.xor
        i32.store offset=4
        i32.const 0
        local.set 2
        loop  ;; label = @3
          local.get 2
          local.get 3
          i32.add
          local.tee 4
          local.get 4
          i32.load
          local.get 2
          local.get 15
          i32.add
          i32.load
          i32.xor
          i32.store
          local.get 2
          i32.const 4
          i32.add
          local.tee 2
          i32.const 32
          i32.ne
          br_if 0 (;@3;)
        end
        local.get 3
        call 4
        local.get 3
        local.get 3
        i32.load offset=24
        local.tee 2
        i32.const 18
        i32.rotl
        i32.const 50529027
        i32.and
        local.get 2
        i32.const 26
        i32.rotl
        i32.const -50529028
        i32.and
        i32.or
        local.tee 6
        local.get 2
        i32.xor
        local.tee 4
        local.get 3
        i32.load offset=28
        local.tee 2
        i32.const 18
        i32.rotl
        i32.const 50529027
        i32.and
        local.get 2
        i32.const 26
        i32.rotl
        i32.const -50529028
        i32.and
        i32.or
        local.tee 5
        local.get 2
        i32.xor
        local.tee 2
        i32.const 12
        i32.rotl
        i32.const 252645135
        i32.and
        local.get 2
        i32.const 20
        i32.rotl
        i32.const -252645136
        i32.and
        i32.or
        i32.xor
        local.get 5
        i32.xor
        i32.store offset=28
        local.get 3
        local.get 6
        local.get 3
        i32.load offset=20
        local.tee 5
        i32.const 18
        i32.rotl
        i32.const 50529027
        i32.and
        local.get 5
        i32.const 26
        i32.rotl
        i32.const -50529028
        i32.and
        i32.or
        local.tee 7
        local.get 5
        i32.xor
        local.tee 5
        local.get 4
        i32.const 12
        i32.rotl
        i32.const 252645135
        i32.and
        local.get 4
        i32.const 20
        i32.rotl
        i32.const -252645136
        i32.and
        i32.or
        i32.xor
        i32.xor
        i32.store offset=24
        local.get 3
        local.get 3
        i32.load offset=16
        local.tee 4
        i32.const 18
        i32.rotl
        i32.const 50529027
        i32.and
        local.get 4
        i32.const 26
        i32.rotl
        i32.const -50529028
        i32.and
        i32.or
        local.tee 10
        local.get 4
        i32.xor
        local.tee 4
        local.get 5
        i32.const 12
        i32.rotl
        i32.const 252645135
        i32.and
        local.get 5
        i32.const 20
        i32.rotl
        i32.const -252645136
        i32.and
        i32.or
        i32.xor
        local.get 7
        i32.xor
        i32.store offset=20
        local.get 3
        local.get 3
        i32.load offset=4
        local.tee 5
        i32.const 18
        i32.rotl
        i32.const 50529027
        i32.and
        local.get 5
        i32.const 26
        i32.rotl
        i32.const -50529028
        i32.and
        i32.or
        local.tee 11
        local.get 5
        i32.xor
        local.tee 5
        local.get 3
        i32.load offset=8
        local.tee 6
        i32.const 18
        i32.rotl
        i32.const 50529027
        i32.and
        local.get 6
        i32.const 26
        i32.rotl
        i32.const -50529028
        i32.and
        i32.or
        local.tee 7
        local.get 6
        i32.xor
        local.tee 6
        i32.const 12
        i32.rotl
        i32.const 252645135
        i32.and
        local.get 6
        i32.const 20
        i32.rotl
        i32.const -252645136
        i32.and
        i32.or
        i32.xor
        local.get 7
        i32.xor
        i32.store offset=8
        local.get 3
        local.get 3
        i32.load
        local.tee 7
        i32.const 18
        i32.rotl
        i32.const 50529027
        i32.and
        local.get 7
        i32.const 26
        i32.rotl
        i32.const -50529028
        i32.and
        i32.or
        local.tee 8
        local.get 7
        i32.xor
        local.tee 7
        i32.const 12
        i32.rotl
        i32.const 252645135
        i32.and
        local.get 7
        i32.const 20
        i32.rotl
        i32.const -252645136
        i32.and
        i32.or
        local.get 8
        i32.xor
        local.get 2
        i32.xor
        i32.store
        local.get 3
        local.get 10
        local.get 3
        i32.load offset=12
        local.tee 8
        i32.const 18
        i32.rotl
        i32.const 50529027
        i32.and
        local.get 8
        i32.const 26
        i32.rotl
        i32.const -50529028
        i32.and
        i32.or
        local.tee 14
        local.get 8
        i32.xor
        local.tee 8
        local.get 4
        i32.const 12
        i32.rotl
        i32.const 252645135
        i32.and
        local.get 4
        i32.const 20
        i32.rotl
        i32.const -252645136
        i32.and
        i32.or
        i32.xor
        i32.xor
        local.get 2
        i32.xor
        i32.store offset=16
        local.get 3
        local.get 6
        local.get 8
        i32.const 12
        i32.rotl
        i32.const 252645135
        i32.and
        local.get 8
        i32.const 20
        i32.rotl
        i32.const -252645136
        i32.and
        i32.or
        i32.xor
        local.get 14
        i32.xor
        local.get 2
        i32.xor
        i32.store offset=12
        local.get 3
        local.get 7
        local.get 5
        i32.const 12
        i32.rotl
        i32.const 252645135
        i32.and
        local.get 5
        i32.const 20
        i32.rotl
        i32.const -252645136
        i32.and
        i32.or
        i32.xor
        local.get 11
        i32.xor
        local.get 2
        i32.xor
        i32.store offset=4
        i32.const 0
        local.set 2
        loop  ;; label = @3
          local.get 2
          local.get 3
          i32.add
          local.tee 4
          local.get 4
          i32.load
          local.get 2
          local.get 13
          i32.add
          i32.load
          i32.xor
          i32.store
          local.get 2
          i32.const 4
          i32.add
          local.tee 2
          i32.const 32
          i32.ne
          br_if 0 (;@3;)
        end
        local.get 3
        call 4
        local.get 3
        local.get 3
        i32.load offset=24
        local.tee 2
        i32.const 24
        i32.rotl
        local.tee 4
        local.get 2
        i32.xor
        local.tee 5
        local.get 3
        i32.load offset=28
        local.tee 2
        i32.const 24
        i32.rotl
        local.tee 6
        local.get 2
        i32.xor
        local.tee 2
        i32.const 16
        i32.rotl
        i32.xor
        local.get 6
        i32.xor
        i32.store offset=28
        local.get 3
        local.get 4
        local.get 3
        i32.load offset=20
        local.tee 6
        i32.const 24
        i32.rotl
        local.tee 7
        local.get 6
        i32.xor
        local.tee 6
        local.get 5
        i32.const 16
        i32.rotl
        i32.xor
        i32.xor
        i32.store offset=24
        local.get 3
        local.get 7
        local.get 3
        i32.load offset=16
        local.tee 4
        i32.const 24
        i32.rotl
        local.tee 5
        local.get 4
        i32.xor
        local.tee 4
        local.get 6
        i32.const 16
        i32.rotl
        i32.xor
        i32.xor
        i32.store offset=20
        local.get 3
        local.get 3
        i32.load offset=4
        local.tee 6
        i32.const 24
        i32.rotl
        local.tee 7
        local.get 6
        i32.xor
        local.tee 6
        local.get 3
        i32.load offset=8
        local.tee 8
        i32.const 24
        i32.rotl
        local.tee 10
        local.get 8
        i32.xor
        local.tee 8
        i32.const 16
        i32.rotl
        i32.xor
        local.get 10
        i32.xor
        i32.store offset=8
        local.get 3
        local.get 3
        i32.load
        local.tee 10
        i32.const 24
        i32.rotl
        local.tee 11
        local.get 10
        i32.xor
        local.tee 10
        i32.const 16
        i32.rotl
        local.get 11
        i32.xor
        local.get 2
        i32.xor
        i32.store
        local.get 3
        local.get 5
        local.get 3
        i32.load offset=12
        local.tee 11
        i32.const 24
        i32.rotl
        local.tee 14
        local.get 11
        i32.xor
        local.tee 11
        local.get 4
        i32.const 16
        i32.rotl
        i32.xor
        i32.xor
        local.get 2
        i32.xor
        i32.store offset=16
        local.get 3
        local.get 8
        local.get 11
        i32.const 16
        i32.rotl
        i32.xor
        local.get 14
        i32.xor
        local.get 2
        i32.xor
        i32.store offset=12
        local.get 3
        local.get 10
        local.get 6
        i32.const 16
        i32.rotl
        i32.xor
        local.get 7
        i32.xor
        local.get 2
        i32.xor
        i32.store offset=4
        i32.const 0
        local.set 2
        loop  ;; label = @3
          local.get 2
          local.get 3
          i32.add
          local.tee 4
          local.get 4
          i32.load
          local.get 2
          local.get 9
          i32.add
          i32.load
          i32.xor
          i32.store
          local.get 2
          i32.const 4
          i32.add
          local.tee 2
          i32.const 32
          i32.ne
          br_if 0 (;@3;)
        end
        local.get 9
        i32.const 128
        i32.add
        local.set 9
        local.get 13
        i32.const 128
        i32.add
        local.set 13
        local.get 15
        i32.const 128
        i32.add
        local.set 15
        local.get 12
        i32.const 128
        i32.add
        local.set 12
        local.get 16
        i32.const 32
        i32.add
        local.set 16
        br 1 (;@1;)
      end
    end)
  (func (;7;) (type 4) (param i32 i32 i32)
    (local i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32)
    local.get 0
    local.get 2
    i32.load offset=12 align=1
    local.tee 3
    local.get 1
    i32.load offset=12 align=1
    local.tee 4
    i32.const 1
    i32.shr_u
    i32.xor
    i32.const 1431655765
    i32.and
    local.tee 8
    local.get 3
    i32.xor
    local.tee 3
    local.get 2
    i32.load offset=8 align=1
    local.tee 5
    local.get 1
    i32.load offset=8 align=1
    local.tee 6
    i32.const 1
    i32.shr_u
    i32.xor
    i32.const 1431655765
    i32.and
    local.tee 9
    local.get 5
    i32.xor
    local.tee 5
    i32.const 2
    i32.shr_u
    i32.xor
    i32.const 858993459
    i32.and
    local.tee 11
    local.get 3
    i32.xor
    local.tee 3
    local.get 2
    i32.load offset=4 align=1
    local.tee 7
    local.get 1
    i32.load offset=4 align=1
    local.tee 10
    i32.const 1
    i32.shr_u
    i32.xor
    i32.const 1431655765
    i32.and
    local.tee 12
    local.get 7
    i32.xor
    local.tee 7
    local.get 2
    i32.load align=1
    local.tee 2
    local.get 1
    i32.load align=1
    local.tee 1
    i32.const 1
    i32.shr_u
    i32.xor
    i32.const 1431655765
    i32.and
    local.tee 13
    local.get 2
    i32.xor
    local.tee 2
    i32.const 2
    i32.shr_u
    i32.xor
    i32.const 858993459
    i32.and
    local.tee 14
    local.get 7
    i32.xor
    local.tee 7
    i32.const 4
    i32.shr_u
    i32.xor
    i32.const 252645135
    i32.and
    local.tee 15
    local.get 3
    i32.xor
    i32.store offset=28
    local.get 0
    local.get 4
    local.get 8
    i32.const 1
    i32.shl
    i32.xor
    local.tee 3
    local.get 6
    local.get 9
    i32.const 1
    i32.shl
    i32.xor
    local.tee 4
    i32.const 2
    i32.shr_u
    i32.xor
    i32.const 858993459
    i32.and
    local.tee 8
    local.get 3
    i32.xor
    local.tee 3
    local.get 10
    local.get 12
    i32.const 1
    i32.shl
    i32.xor
    local.tee 6
    local.get 1
    local.get 13
    i32.const 1
    i32.shl
    i32.xor
    local.tee 1
    i32.const 2
    i32.shr_u
    i32.xor
    i32.const 858993459
    i32.and
    local.tee 9
    local.get 6
    i32.xor
    local.tee 6
    i32.const 4
    i32.shr_u
    i32.xor
    i32.const 252645135
    i32.and
    local.tee 10
    local.get 3
    i32.xor
    i32.store offset=24
    local.get 0
    local.get 11
    i32.const 2
    i32.shl
    local.get 5
    i32.xor
    local.tee 3
    local.get 14
    i32.const 2
    i32.shl
    local.get 2
    i32.xor
    local.tee 2
    i32.const 4
    i32.shr_u
    i32.xor
    i32.const 252645135
    i32.and
    local.tee 5
    local.get 3
    i32.xor
    i32.store offset=20
    local.get 0
    local.get 15
    i32.const 4
    i32.shl
    local.get 7
    i32.xor
    i32.store offset=12
    local.get 0
    local.get 8
    i32.const 2
    i32.shl
    local.get 4
    i32.xor
    local.tee 3
    local.get 9
    i32.const 2
    i32.shl
    local.get 1
    i32.xor
    local.tee 1
    i32.const 4
    i32.shr_u
    i32.xor
    i32.const 252645135
    i32.and
    local.tee 4
    local.get 3
    i32.xor
    i32.store offset=16
    local.get 0
    local.get 10
    i32.const 4
    i32.shl
    local.get 6
    i32.xor
    i32.store offset=8
    local.get 0
    local.get 5
    i32.const 4
    i32.shl
    local.get 2
    i32.xor
    i32.store offset=4
    local.get 0
    local.get 4
    i32.const 4
    i32.shl
    local.get 1
    i32.xor
    i32.store)
  (func (;8;) (type 0) (param i32 i32) (result i32)
    (local i32 i32 i32 i32 i32)
    block  ;; label = @1
      local.get 1
      i32.const -65587
      i32.const 16
      local.get 0
      local.get 0
      i32.const 16
      i32.le_u
      select
      local.tee 0
      i32.sub
      i32.ge_u
      br_if 0 (;@1;)
      local.get 0
      i32.const 16
      local.get 1
      i32.const 11
      i32.add
      i32.const -8
      i32.and
      local.get 1
      i32.const 11
      i32.lt_u
      select
      local.tee 4
      i32.add
      i32.const 12
      i32.add
      call 1
      local.tee 2
      i32.eqz
      br_if 0 (;@1;)
      local.get 2
      i32.const 8
      i32.sub
      local.set 1
      block  ;; label = @2
        local.get 0
        i32.const 1
        i32.sub
        local.tee 3
        local.get 2
        i32.and
        i32.eqz
        if  ;; label = @3
          local.get 1
          local.set 0
          br 1 (;@2;)
        end
        local.get 2
        i32.const 4
        i32.sub
        local.tee 5
        i32.load
        local.tee 6
        i32.const -8
        i32.and
        local.get 2
        local.get 3
        i32.add
        i32.const 0
        local.get 0
        i32.sub
        i32.and
        i32.const 8
        i32.sub
        local.tee 2
        local.get 0
        i32.const 0
        local.get 2
        local.get 1
        i32.sub
        i32.const 16
        i32.le_u
        select
        i32.add
        local.tee 0
        local.get 1
        i32.sub
        local.tee 2
        i32.sub
        local.set 3
        local.get 6
        i32.const 3
        i32.and
        if  ;; label = @3
          local.get 0
          local.get 3
          local.get 0
          i32.load offset=4
          i32.const 1
          i32.and
          i32.or
          i32.const 2
          i32.or
          i32.store offset=4
          local.get 0
          local.get 3
          i32.add
          local.tee 3
          local.get 3
          i32.load offset=4
          i32.const 1
          i32.or
          i32.store offset=4
          local.get 5
          local.get 2
          local.get 5
          i32.load
          i32.const 1
          i32.and
          i32.or
          i32.const 2
          i32.or
          i32.store
          local.get 1
          local.get 2
          i32.add
          local.tee 3
          local.get 3
          i32.load offset=4
          i32.const 1
          i32.or
          i32.store offset=4
          local.get 1
          local.get 2
          call 3
          br 1 (;@2;)
        end
        local.get 1
        i32.load
        local.set 1
        local.get 0
        local.get 3
        i32.store offset=4
        local.get 0
        local.get 1
        local.get 2
        i32.add
        i32.store
      end
      block  ;; label = @2
        local.get 0
        i32.load offset=4
        local.tee 1
        i32.const 3
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.const -8
        i32.and
        local.tee 2
        local.get 4
        i32.const 16
        i32.add
        i32.le_u
        br_if 0 (;@2;)
        local.get 0
        local.get 4
        local.get 1
        i32.const 1
        i32.and
        i32.or
        i32.const 2
        i32.or
        i32.store offset=4
        local.get 0
        local.get 4
        i32.add
        local.tee 1
        local.get 2
        local.get 4
        i32.sub
        local.tee 4
        i32.const 3
        i32.or
        i32.store offset=4
        local.get 0
        local.get 2
        i32.add
        local.tee 2
        local.get 2
        i32.load offset=4
        i32.const 1
        i32.or
        i32.store offset=4
        local.get 1
        local.get 4
        call 3
      end
      local.get 0
      i32.const 8
      i32.add
      local.set 3
    end
    local.get 3)
  (func (;9;) (type 1) (param i32 i32)
    (local i32 i32 i32 i32)
    block  ;; label = @1
      block  ;; label = @2
        block  ;; label = @3
          local.get 1
          i32.const 256
          i32.ge_u
          if  ;; label = @4
            local.get 0
            i32.load offset=24
            local.set 3
            block  ;; label = @5
              block  ;; label = @6
                local.get 0
                local.get 0
                i32.load offset=12
                local.tee 1
                i32.eq
                if  ;; label = @7
                  local.get 0
                  i32.const 20
                  i32.const 16
                  local.get 0
                  i32.load offset=20
                  local.tee 1
                  select
                  i32.add
                  i32.load
                  local.tee 2
                  br_if 1 (;@6;)
                  i32.const 0
                  local.set 1
                  br 2 (;@5;)
                end
                local.get 0
                i32.load offset=8
                local.tee 2
                local.get 1
                i32.store offset=12
                local.get 1
                local.get 2
                i32.store offset=8
                br 1 (;@5;)
              end
              local.get 0
              i32.const 20
              i32.add
              local.get 0
              i32.const 16
              i32.add
              local.get 1
              select
              local.set 4
              loop  ;; label = @6
                local.get 4
                local.set 5
                local.get 2
                local.tee 1
                i32.const 20
                i32.add
                local.get 1
                i32.const 16
                i32.add
                local.get 1
                i32.load offset=20
                local.tee 2
                select
                local.set 4
                local.get 1
                i32.const 20
                i32.const 16
                local.get 2
                select
                i32.add
                i32.load
                local.tee 2
                br_if 0 (;@6;)
              end
              local.get 5
              i32.const 0
              i32.store
            end
            local.get 3
            i32.eqz
            br_if 2 (;@2;)
            block  ;; label = @5
              local.get 0
              i32.load offset=28
              local.tee 2
              i32.const 2
              i32.shl
              i32.const 1050276
              i32.add
              local.tee 4
              i32.load
              local.get 0
              i32.ne
              if  ;; label = @6
                local.get 3
                i32.load offset=16
                local.get 0
                i32.eq
                br_if 1 (;@5;)
                local.get 3
                local.get 1
                i32.store offset=20
                local.get 1
                br_if 3 (;@3;)
                br 4 (;@2;)
              end
              local.get 4
              local.get 1
              i32.store
              local.get 1
              i32.eqz
              br_if 4 (;@1;)
              br 2 (;@3;)
            end
            local.get 3
            local.get 1
            i32.store offset=16
            local.get 1
            br_if 1 (;@3;)
            br 2 (;@2;)
          end
          local.get 0
          i32.load offset=12
          local.tee 2
          local.get 0
          i32.load offset=8
          local.tee 0
          i32.ne
          if  ;; label = @4
            local.get 0
            local.get 2
            i32.store offset=12
            local.get 2
            local.get 0
            i32.store offset=8
            return
          end
          i32.const 1050684
          i32.const 1050684
          i32.load
          i32.const -2
          local.get 1
          i32.const 3
          i32.shr_u
          i32.rotl
          i32.and
          i32.store
          return
        end
        local.get 1
        local.get 3
        i32.store offset=24
        local.get 0
        i32.load offset=16
        local.tee 2
        if  ;; label = @3
          local.get 1
          local.get 2
          i32.store offset=16
          local.get 2
          local.get 1
          i32.store offset=24
        end
        local.get 0
        i32.load offset=20
        local.tee 0
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        local.get 0
        i32.store offset=20
        local.get 0
        local.get 1
        i32.store offset=24
        return
      end
      return
    end
    i32.const 1050688
    i32.const 1050688
    i32.load
    i32.const -2
    local.get 2
    i32.rotl
    i32.and
    i32.store)
  (func (;10;) (type 0) (param i32 i32) (result i32)
    (local i32 i32 i32 i32 i32)
    global.get 0
    i32.const 16
    i32.sub
    local.tee 2
    global.set 0
    block  ;; label = @1
      local.get 1
      i32.const 128
      i32.ge_u
      if  ;; label = @2
        local.get 2
        i32.const 0
        i32.store offset=12
        block (result i32)  ;; label = @3
          local.get 1
          i32.const 2048
          i32.ge_u
          if  ;; label = @4
            local.get 1
            i32.const 65536
            i32.ge_u
            if  ;; label = @5
              local.get 2
              local.get 1
              i32.const 63
              i32.and
              i32.const 128
              i32.or
              i32.store8 offset=15
              local.get 2
              local.get 1
              i32.const 18
              i32.shr_u
              i32.const 240
              i32.or
              i32.store8 offset=12
              local.get 2
              local.get 1
              i32.const 6
              i32.shr_u
              i32.const 63
              i32.and
              i32.const 128
              i32.or
              i32.store8 offset=14
              local.get 2
              local.get 1
              i32.const 12
              i32.shr_u
              i32.const 63
              i32.and
              i32.const 128
              i32.or
              i32.store8 offset=13
              local.get 2
              i32.const 16
              i32.add
              br 2 (;@3;)
            end
            local.get 2
            local.get 1
            i32.const 63
            i32.and
            i32.const 128
            i32.or
            i32.store8 offset=14
            local.get 2
            local.get 1
            i32.const 12
            i32.shr_u
            i32.const 224
            i32.or
            i32.store8 offset=12
            local.get 2
            local.get 1
            i32.const 6
            i32.shr_u
            i32.const 63
            i32.and
            i32.const 128
            i32.or
            i32.store8 offset=13
            local.get 2
            i32.const 12
            i32.add
            i32.const 3
            i32.or
            br 1 (;@3;)
          end
          local.get 2
          local.get 1
          i32.const 63
          i32.and
          i32.const 128
          i32.or
          i32.store8 offset=13
          local.get 2
          local.get 1
          i32.const 6
          i32.shr_u
          i32.const 192
          i32.or
          i32.store8 offset=12
          local.get 2
          i32.const 12
          i32.add
          i32.const 2
          i32.or
        end
        local.get 2
        i32.const 12
        i32.add
        i32.sub
        local.tee 1
        local.get 0
        i32.load
        local.get 0
        i32.load offset=8
        local.tee 3
        i32.sub
        i32.gt_u
        if  ;; label = @3
          local.get 0
          local.get 3
          local.get 1
          call 12
          local.get 0
          i32.load offset=8
          local.set 3
        end
        local.get 1
        if  ;; label = @3
          local.get 0
          i32.load offset=4
          local.get 3
          i32.add
          local.get 2
          i32.const 12
          i32.add
          local.get 1
          memory.copy
        end
        local.get 0
        local.get 1
        local.get 3
        i32.add
        i32.store offset=8
        br 1 (;@1;)
      end
      local.get 0
      i32.load offset=8
      local.tee 6
      local.get 0
      i32.load
      i32.eq
      if  ;; label = @2
        global.get 0
        i32.const 32
        i32.sub
        local.tee 3
        global.set 0
        i32.const 8
        local.get 0
        i32.load
        local.tee 4
        i32.const 1
        i32.shl
        local.tee 5
        local.get 5
        i32.const 8
        i32.le_u
        select
        local.tee 5
        i32.const 0
        i32.lt_s
        if  ;; label = @3
          i32.const 0
          i32.const 0
          i32.const 1049556
          call 32
          unreachable
        end
        local.get 3
        local.get 4
        if (result i32)  ;; label = @3
          local.get 3
          local.get 4
          i32.store offset=28
          local.get 3
          local.get 0
          i32.load offset=4
          i32.store offset=20
          i32.const 1
        else
          i32.const 0
        end
        i32.store offset=24
        local.get 3
        i32.const 8
        i32.add
        local.get 5
        local.get 3
        i32.const 20
        i32.add
        call 16
        local.get 3
        i32.load offset=8
        i32.const 1
        i32.eq
        if  ;; label = @3
          local.get 3
          i32.load offset=12
          local.get 3
          i32.load offset=16
          i32.const 1049556
          call 32
          unreachable
        end
        local.get 3
        i32.load offset=12
        local.set 4
        local.get 0
        local.get 5
        i32.store
        local.get 0
        local.get 4
        i32.store offset=4
        local.get 3
        i32.const 32
        i32.add
        global.set 0
      end
      local.get 0
      i32.load offset=4
      local.get 6
      i32.add
      local.get 1
      i32.store8
      local.get 0
      local.get 6
      i32.const 1
      i32.add
      i32.store offset=8
    end
    local.get 2
    i32.const 16
    i32.add
    global.set 0
    i32.const 0)
  (func (;11;) (type 1) (param i32 i32)
    (local i32 i32 i32 i32)
    i32.const 31
    local.set 2
    local.get 0
    i64.const 0
    i64.store offset=16 align=4
    local.get 1
    i32.const 16777215
    i32.le_u
    if  ;; label = @1
      local.get 1
      i32.const 6
      local.get 1
      i32.const 8
      i32.shr_u
      i32.clz
      local.tee 3
      i32.sub
      i32.shr_u
      i32.const 1
      i32.and
      local.get 3
      i32.const 1
      i32.shl
      i32.sub
      i32.const 62
      i32.add
      local.set 2
    end
    local.get 0
    local.get 2
    i32.store offset=28
    local.get 2
    i32.const 2
    i32.shl
    i32.const 1050276
    i32.add
    local.set 4
    block  ;; label = @1
      i32.const 1
      local.get 2
      i32.shl
      local.tee 3
      i32.const 1050688
      i32.load
      i32.and
      i32.eqz
      if  ;; label = @2
        local.get 4
        local.get 0
        i32.store
        local.get 0
        local.get 4
        i32.store offset=24
        i32.const 1050688
        i32.const 1050688
        i32.load
        local.get 3
        i32.or
        i32.store
        br 1 (;@1;)
      end
      block  ;; label = @2
        block  ;; label = @3
          local.get 1
          local.get 4
          i32.load
          local.tee 3
          i32.load offset=4
          i32.const -8
          i32.and
          i32.eq
          if  ;; label = @4
            local.get 3
            local.set 2
            br 1 (;@3;)
          end
          local.get 1
          i32.const 25
          local.get 2
          i32.const 1
          i32.shr_u
          i32.sub
          i32.const 0
          local.get 2
          i32.const 31
          i32.ne
          select
          i32.shl
          local.set 5
          loop  ;; label = @4
            local.get 3
            local.get 5
            i32.const 29
            i32.shr_u
            i32.const 4
            i32.and
            i32.add
            local.tee 4
            i32.load offset=16
            local.tee 2
            i32.eqz
            br_if 2 (;@2;)
            local.get 5
            i32.const 1
            i32.shl
            local.set 5
            local.get 2
            local.set 3
            local.get 2
            i32.load offset=4
            i32.const -8
            i32.and
            local.get 1
            i32.ne
            br_if 0 (;@4;)
          end
        end
        local.get 2
        i32.load offset=8
        local.tee 1
        local.get 0
        i32.store offset=12
        local.get 2
        local.get 0
        i32.store offset=8
        local.get 0
        i32.const 0
        i32.store offset=24
        local.get 0
        local.get 2
        i32.store offset=12
        local.get 0
        local.get 1
        i32.store offset=8
        return
      end
      local.get 4
      i32.const 16
      i32.add
      local.get 0
      i32.store
      local.get 0
      local.get 3
      i32.store offset=24
    end
    local.get 0
    local.get 0
    i32.store offset=12
    local.get 0
    local.get 0
    i32.store offset=8)
  (func (;12;) (type 4) (param i32 i32 i32)
    (local i32 i32 i32 i32 i64)
    global.get 0
    i32.const 32
    i32.sub
    local.tee 3
    global.set 0
    block  ;; label = @1
      block  ;; label = @2
        local.get 1
        local.get 1
        local.get 2
        i32.add
        local.tee 2
        i32.gt_u
        br_if 0 (;@2;)
        i32.const 8
        local.get 2
        local.get 0
        i32.load
        local.tee 1
        i32.const 1
        i32.shl
        local.tee 4
        local.get 2
        local.get 4
        i32.gt_u
        select
        local.tee 2
        local.get 2
        i32.const 8
        i32.le_u
        select
        local.tee 4
        i64.extend_i32_u
        local.tee 7
        i64.const 32
        i64.shr_u
        i64.eqz
        i32.eqz
        br_if 0 (;@2;)
        local.get 7
        i32.wrap_i64
        local.tee 5
        i32.const 2147483647
        i32.gt_u
        br_if 0 (;@2;)
        local.get 3
        local.get 1
        if (result i32)  ;; label = @3
          local.get 3
          local.get 1
          i32.store offset=28
          local.get 3
          local.get 0
          i32.load offset=4
          i32.store offset=20
          i32.const 1
        else
          i32.const 0
        end
        i32.store offset=24
        local.get 3
        i32.const 8
        i32.add
        local.get 5
        local.get 3
        i32.const 20
        i32.add
        call 16
        local.get 3
        i32.load offset=8
        i32.const 1
        i32.ne
        br_if 1 (;@1;)
        local.get 3
        i32.load offset=16
        local.set 2
        local.get 3
        i32.load offset=12
        local.set 6
      end
      local.get 6
      local.get 2
      i32.const 1049488
      call 32
      unreachable
    end
    local.get 3
    i32.load offset=12
    local.set 1
    local.get 0
    local.get 4
    i32.store
    local.get 0
    local.get 1
    i32.store offset=4
    local.get 3
    i32.const 32
    i32.add
    global.set 0)
  (func (;13;) (type 1) (param i32 i32)
    (local i32 i32 i32 i64)
    global.get 0
    i32.const -64
    i32.add
    local.tee 2
    global.set 0
    local.get 1
    i32.load
    i32.const -2147483648
    i32.eq
    if  ;; label = @1
      local.get 1
      i32.load offset=12
      local.set 3
      local.get 2
      i32.const 36
      i32.add
      local.tee 4
      i32.const 0
      i32.store
      local.get 2
      i64.const 4294967296
      i64.store offset=28 align=4
      local.get 2
      i32.const 48
      i32.add
      local.get 3
      i32.load
      local.tee 3
      i32.const 8
      i32.add
      i64.load align=4
      i64.store
      local.get 2
      i32.const 56
      i32.add
      local.get 3
      i32.const 16
      i32.add
      i64.load align=4
      i64.store
      local.get 2
      local.get 3
      i64.load align=4
      i64.store offset=40
      local.get 2
      i32.const 28
      i32.add
      i32.const 1049572
      local.get 2
      i32.const 40
      i32.add
      call 5
      drop
      local.get 2
      i32.const 24
      i32.add
      local.get 4
      i32.load
      local.tee 3
      i32.store
      local.get 2
      local.get 2
      i64.load offset=28 align=4
      local.tee 5
      i64.store offset=16
      local.get 1
      i32.const 8
      i32.add
      local.get 3
      i32.store
      local.get 1
      local.get 5
      i64.store align=4
    end
    local.get 1
    i64.load align=4
    local.set 5
    local.get 1
    i64.const 4294967296
    i64.store align=4
    local.get 2
    i32.const 8
    i32.add
    local.tee 3
    local.get 1
    i32.const 8
    i32.add
    local.tee 1
    i32.load
    i32.store
    local.get 1
    i32.const 0
    i32.store
    i32.const 1050233
    i32.load8_u
    drop
    local.get 2
    local.get 5
    i64.store
    i32.const 12
    i32.const 4
    call 39
    local.tee 1
    i32.eqz
    if  ;; label = @1
      i32.const 4
      i32.const 12
      call 50
      unreachable
    end
    local.get 1
    local.get 2
    i64.load
    i64.store align=4
    local.get 1
    i32.const 8
    i32.add
    local.get 3
    i32.load
    i32.store
    local.get 0
    i32.const 1049596
    i32.store offset=4
    local.get 0
    local.get 1
    i32.store
    local.get 2
    i32.const -64
    i32.sub
    global.set 0)
  (func (;14;) (type 8) (param i32 i32 i32 i32 i32)
    (local i32 i32)
    global.get 0
    i32.const 32
    i32.sub
    local.tee 5
    global.set 0
    i32.const 1050264
    i32.const 1050264
    i32.load
    local.tee 6
    i32.const 1
    i32.add
    i32.store
    block  ;; label = @1
      block (result i32)  ;; label = @2
        i32.const 0
        local.get 6
        i32.const 0
        i32.lt_s
        br_if 0 (;@2;)
        drop
        i32.const 1
        i32.const 1050272
        i32.load8_u
        br_if 0 (;@2;)
        drop
        i32.const 1050272
        i32.const 1
        i32.store8
        i32.const 1050268
        i32.const 1050268
        i32.load
        i32.const 1
        i32.add
        i32.store
        i32.const 2
      end
      i32.const 255
      i32.and
      local.tee 6
      i32.const 2
      i32.ne
      if  ;; label = @2
        local.get 6
        i32.const 1
        i32.and
        i32.eqz
        br_if 1 (;@1;)
        local.get 5
        i32.const 8
        i32.add
        local.get 0
        local.get 1
        i32.load offset=24
        call_indirect (type 1)
        br 1 (;@1;)
      end
      i32.const 1050252
      i32.load
      local.tee 6
      i32.const 0
      i32.ge_s
      if  ;; label = @2
        i32.const 1050252
        local.get 6
        i32.const 1
        i32.add
        i32.store
        block  ;; label = @3
          i32.const 1050256
          i32.load
          if  ;; label = @4
            local.get 5
            local.get 0
            local.get 1
            i32.load offset=20
            call_indirect (type 1)
            local.get 5
            local.get 4
            i32.store8 offset=29
            local.get 5
            local.get 3
            i32.store8 offset=28
            local.get 5
            local.get 2
            i32.store offset=24
            local.get 5
            local.get 5
            i64.load
            i64.store offset=16 align=4
            i32.const 1050256
            i32.load
            local.get 5
            i32.const 16
            i32.add
            i32.const 1050260
            i32.load
            i32.load offset=20
            call_indirect (type 1)
            br 1 (;@3;)
          end
          local.get 5
          i32.const -2147483648
          i32.store offset=16
          local.get 5
          i32.const 16
          i32.add
          call 30
        end
        i32.const 1050252
        i32.const 1050252
        i32.load
        i32.const 1
        i32.sub
        i32.store
        i32.const 1050272
        i32.const 0
        i32.store8
        local.get 3
        i32.eqz
        br_if 1 (;@1;)
        global.get 0
        i32.const 16
        i32.sub
        global.set 0
        unreachable
      end
    end
    local.get 5
    i32.const -2147483648
    i32.store offset=16
    local.get 5
    i32.const 16
    i32.add
    call 30
    unreachable)
  (func (;15;) (type 1) (param i32 i32)
    (local i32 i32 i32 i64)
    global.get 0
    i32.const 48
    i32.sub
    local.tee 2
    global.set 0
    local.get 1
    i32.load
    i32.const -2147483648
    i32.eq
    if  ;; label = @1
      local.get 1
      i32.load offset=12
      local.set 3
      local.get 2
      i32.const 20
      i32.add
      local.tee 4
      i32.const 0
      i32.store
      local.get 2
      i64.const 4294967296
      i64.store offset=12 align=4
      local.get 2
      i32.const 32
      i32.add
      local.get 3
      i32.load
      local.tee 3
      i32.const 8
      i32.add
      i64.load align=4
      i64.store
      local.get 2
      i32.const 40
      i32.add
      local.get 3
      i32.const 16
      i32.add
      i64.load align=4
      i64.store
      local.get 2
      local.get 3
      i64.load align=4
      i64.store offset=24
      local.get 2
      i32.const 12
      i32.add
      i32.const 1049572
      local.get 2
      i32.const 24
      i32.add
      call 5
      drop
      local.get 2
      i32.const 8
      i32.add
      local.get 4
      i32.load
      local.tee 3
      i32.store
      local.get 2
      local.get 2
      i64.load offset=12 align=4
      local.tee 5
      i64.store
      local.get 1
      i32.const 8
      i32.add
      local.get 3
      i32.store
      local.get 1
      local.get 5
      i64.store align=4
    end
    local.get 0
    i32.const 1049596
    i32.store offset=4
    local.get 0
    local.get 1
    i32.store
    local.get 2
    i32.const 48
    i32.add
    global.set 0)
  (func (;16;) (type 4) (param i32 i32 i32)
    (local i32)
    local.get 1
    i32.const 0
    i32.ge_s
    if  ;; label = @1
      block (result i32)  ;; label = @2
        local.get 2
        i32.load offset=4
        if  ;; label = @3
          local.get 2
          i32.load offset=8
          local.tee 3
          if  ;; label = @4
            local.get 2
            i32.load
            local.get 3
            i32.const 1
            local.get 1
            call 35
            br 2 (;@2;)
          end
        end
        i32.const 1
        local.get 1
        i32.eqz
        br_if 0 (;@2;)
        drop
        i32.const 1050233
        i32.load8_u
        drop
        local.get 1
        i32.const 1
        call 39
      end
      local.tee 2
      i32.eqz
      if  ;; label = @2
        local.get 0
        local.get 1
        i32.store offset=8
        local.get 0
        i32.const 1
        i32.store offset=4
        local.get 0
        i32.const 1
        i32.store
        return
      end
      local.get 0
      local.get 1
      i32.store offset=8
      local.get 0
      local.get 2
      i32.store offset=4
      local.get 0
      i32.const 0
      i32.store
      return
    end
    local.get 0
    i32.const 0
    i32.store offset=4
    local.get 0
    i32.const 1
    i32.store)
  (func (;17;) (type 0) (param i32 i32) (result i32)
    (local i32)
    global.get 0
    i32.const 32
    i32.sub
    local.tee 2
    global.set 0
    block (result i32)  ;; label = @1
      local.get 0
      i32.load
      i32.const -2147483648
      i32.ne
      if  ;; label = @2
        local.get 1
        local.get 0
        i32.load offset=4
        local.get 0
        i32.load offset=8
        call 37
        br 1 (;@1;)
      end
      local.get 2
      i32.const 16
      i32.add
      local.get 0
      i32.load offset=12
      i32.load
      local.tee 0
      i32.const 8
      i32.add
      i64.load align=4
      i64.store
      local.get 2
      i32.const 24
      i32.add
      local.get 0
      i32.const 16
      i32.add
      i64.load align=4
      i64.store
      local.get 2
      local.get 0
      i64.load align=4
      i64.store offset=8
      local.get 1
      i32.load
      local.get 1
      i32.load offset=4
      local.get 2
      i32.const 8
      i32.add
      call 5
    end
    local.get 2
    i32.const 32
    i32.add
    global.set 0)
  (func (;18;) (type 3) (param i32)
    (local i32 i32 i32 i32 i32)
    i32.const 1
    local.set 3
    global.get 0
    i32.const 16
    i32.sub
    local.tee 1
    global.set 0
    local.get 1
    i32.const 12
    i32.add
    local.set 4
    local.get 0
    i32.load
    local.tee 2
    if  ;; label = @1
      local.get 1
      i32.const 1
      i32.store offset=12
      local.get 0
      i32.load offset=4
      local.set 3
      local.get 1
      i32.const 8
      i32.add
      local.set 4
      local.get 2
      local.set 5
    end
    local.get 4
    local.get 5
    i32.store
    block  ;; label = @1
      local.get 1
      i32.load offset=12
      local.tee 0
      i32.eqz
      br_if 0 (;@1;)
      local.get 1
      i32.load offset=8
      local.tee 2
      i32.eqz
      br_if 0 (;@1;)
      local.get 3
      local.get 2
      call 45
    end
    local.get 1
    i32.const 16
    i32.add
    global.set 0)
  (func (;19;) (type 1) (param i32 i32)
    (local i32)
    global.get 0
    i32.const 48
    i32.sub
    local.tee 2
    global.set 0
    local.get 2
    i32.const 88
    i32.store offset=4
    local.get 2
    local.get 0
    i32.store
    local.get 2
    i32.const 2
    i32.store offset=12
    local.get 2
    i32.const 1050168
    i32.store offset=8
    local.get 2
    i64.const 2
    i64.store offset=20 align=4
    local.get 2
    local.get 2
    i64.extend_i32_u
    i64.const 12884901888
    i64.or
    i64.store offset=40
    local.get 2
    local.get 2
    i32.const 4
    i32.add
    i64.extend_i32_u
    i64.const 12884901888
    i64.or
    i64.store offset=32
    local.get 2
    local.get 2
    i32.const 32
    i32.add
    i32.store offset=16
    local.get 2
    i32.const 8
    i32.add
    local.get 1
    call 28
    unreachable)
  (func (;20;) (type 1) (param i32 i32)
    global.get 0
    i32.const 48
    i32.sub
    local.tee 0
    global.set 0
    i32.const 1050232
    i32.load8_u
    i32.eqz
    if  ;; label = @1
      local.get 0
      i32.const 48
      i32.add
      global.set 0
      return
    end
    local.get 0
    i32.const 2
    i32.store offset=12
    local.get 0
    i32.const 1049376
    i32.store offset=8
    local.get 0
    i64.const 1
    i64.store offset=20 align=4
    local.get 0
    local.get 1
    i32.store offset=44
    local.get 0
    local.get 0
    i32.const 44
    i32.add
    i64.extend_i32_u
    i64.const 12884901888
    i64.or
    i64.store offset=32
    local.get 0
    local.get 0
    i32.const 32
    i32.add
    i32.store offset=16
    local.get 0
    i32.const 8
    i32.add
    i32.const 1049416
    call 28
    unreachable)
  (func (;21;) (type 2) (param i32 i32 i32) (result i32)
    (local i32)
    local.get 0
    i32.load
    local.get 0
    i32.load offset=8
    local.tee 3
    i32.sub
    local.get 2
    i32.lt_u
    if  ;; label = @1
      local.get 0
      local.get 3
      local.get 2
      call 12
      local.get 0
      i32.load offset=8
      local.set 3
    end
    local.get 2
    if  ;; label = @1
      local.get 0
      i32.load offset=4
      local.get 3
      i32.add
      local.get 1
      local.get 2
      memory.copy
    end
    local.get 0
    local.get 2
    local.get 3
    i32.add
    i32.store offset=8
    i32.const 0)
  (func (;22;) (type 1) (param i32 i32)
    (local i32 i32)
    i32.const 1050233
    i32.load8_u
    drop
    local.get 1
    i32.load offset=4
    local.set 2
    local.get 1
    i32.load
    local.set 3
    i32.const 8
    i32.const 4
    call 39
    local.tee 1
    i32.eqz
    if  ;; label = @1
      i32.const 4
      i32.const 8
      call 50
      unreachable
    end
    local.get 1
    local.get 2
    i32.store offset=4
    local.get 1
    local.get 3
    i32.store
    local.get 0
    i32.const 1049612
    i32.store offset=4
    local.get 0
    local.get 1
    i32.store)
  (func (;23;) (type 0) (param i32 i32) (result i32)
    (local i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i64 i64 i64 i64)
    global.get 0
    i32.const 32
    i32.sub
    local.tee 16
    global.set 0
    global.get 0
    i32.const 32
    i32.sub
    local.tee 2
    global.set 0
    local.get 2
    local.get 1
    i32.store offset=28
    local.get 2
    local.get 0
    i32.store offset=24
    local.get 2
    local.get 1
    i32.store offset=20
    i32.const 0
    local.set 0
    global.get 0
    i32.const 16
    i32.sub
    local.tee 6
    global.set 0
    block  ;; label = @1
      block  ;; label = @2
        local.get 2
        i32.const 8
        i32.add
        local.tee 11
        local.get 2
        i32.const 20
        i32.add
        local.tee 9
        i32.load offset=8
        local.tee 1
        local.get 9
        i32.load
        i32.lt_u
        if (result i32)  ;; label = @3
          i32.const 1
          local.set 3
          global.get 0
          i32.const 16
          i32.sub
          local.tee 10
          global.set 0
          local.get 10
          i32.const 12
          i32.add
          local.set 4
          local.get 9
          i32.load
          local.tee 8
          if  ;; label = @4
            local.get 10
            i32.const 1
            i32.store offset=12
            local.get 9
            i32.load offset=4
            local.set 5
            local.get 10
            i32.const 8
            i32.add
            local.set 4
            local.get 8
            local.set 0
          end
          local.get 6
          i32.const 8
          i32.add
          local.set 7
          local.get 4
          local.get 0
          i32.store
          block  ;; label = @4
            local.get 10
            i32.load offset=12
            local.tee 0
            if  ;; label = @5
              local.get 10
              i32.load offset=8
              local.set 8
              block  ;; label = @6
                local.get 1
                i32.eqz
                if  ;; label = @7
                  local.get 8
                  i32.eqz
                  br_if 1 (;@6;)
                  local.get 5
                  local.get 8
                  call 45
                  br 1 (;@6;)
                end
                local.get 5
                local.get 8
                local.get 0
                local.get 1
                local.tee 4
                call 35
                local.tee 3
                i32.eqz
                br_if 2 (;@4;)
              end
              local.get 9
              local.get 1
              i32.store
              local.get 9
              local.get 3
              i32.store offset=4
            end
            i32.const -2147483647
            local.set 0
          end
          local.get 7
          local.get 4
          i32.store offset=4
          local.get 7
          local.get 0
          i32.store
          local.get 10
          i32.const 16
          i32.add
          global.set 0
          local.get 6
          i32.load offset=8
          local.tee 0
          i32.const -2147483647
          i32.ne
          br_if 1 (;@2;)
          local.get 9
          i32.load offset=8
        else
          local.get 1
        end
        i32.store offset=4
        local.get 11
        local.get 9
        i32.load offset=4
        i32.store
        local.get 6
        i32.const 16
        i32.add
        global.set 0
        br 1 (;@1;)
      end
      local.get 0
      local.get 6
      i32.load offset=12
      i32.const 1049324
      call 32
      unreachable
    end
    local.get 16
    i32.const 8
    i32.add
    local.get 2
    i64.load offset=8
    i64.store
    local.get 2
    i32.const 32
    i32.add
    global.set 0
    local.get 16
    i32.load offset=8
    local.set 0
    local.get 16
    i32.const 20
    i32.add
    local.tee 17
    local.get 16
    i32.load offset=12
    local.tee 1
    i32.store offset=8
    local.get 17
    local.get 0
    i32.store offset=4
    local.get 17
    local.get 1
    i32.store
    block (result i32)  ;; label = @1
      global.get 0
      i32.const 32
      i32.sub
      local.tee 12
      global.set 0
      local.get 12
      i32.const 8
      i32.add
      local.set 20
      local.get 17
      i32.load offset=4
      local.set 13
      local.get 17
      i32.load offset=8
      local.set 11
      i32.const 0
      local.set 9
      i32.const 0
      local.set 6
      i32.const 0
      local.set 10
      global.get 0
      i32.const 816
      i32.sub
      local.tee 5
      global.set 0
      local.get 5
      i32.const 424
      i32.add
      i32.const 1048836
      i64.load align=1
      i64.store
      local.get 5
      i32.const 1048828
      i64.load align=1
      i64.store offset=416
      local.get 5
      i32.const 432
      i32.add
      local.set 8
      global.get 0
      i32.const 352
      i32.sub
      local.tee 4
      global.set 0
      local.get 4
      i32.const 32
      i32.add
      i32.const 0
      i32.const 320
      memory.fill
      local.get 4
      local.get 5
      i32.const 416
      i32.add
      local.tee 0
      local.get 0
      call 7
      i32.const 8
      local.set 0
      loop  ;; label = @2
        local.get 0
        i32.const 8
        i32.sub
        local.tee 2
        i32.const 15
        i32.add
        local.set 1
        local.get 4
        local.get 2
        i32.const 2
        i32.shl
        i32.add
        local.set 3
        i32.const 32
        local.set 2
        block  ;; label = @3
          block  ;; label = @4
            block  ;; label = @5
              loop  ;; label = @6
                local.get 1
                i32.const 8
                i32.sub
                i32.const 88
                i32.ge_u
                br_if 2 (;@4;)
                local.get 1
                i32.const 88
                i32.ge_u
                br_if 1 (;@5;)
                local.get 2
                local.get 3
                i32.add
                local.tee 7
                i32.const 28
                i32.add
                local.get 7
                i32.const 4
                i32.sub
                i32.load
                i32.store
                local.get 1
                i32.const 1
                i32.sub
                local.set 1
                local.get 2
                i32.const 4
                i32.sub
                local.tee 2
                br_if 0 (;@6;)
              end
              br 2 (;@3;)
            end
            local.get 1
            i32.const 1048992
            call 19
            unreachable
          end
          local.get 1
          i32.const 8
          i32.sub
          i32.const 1048976
          call 19
          unreachable
        end
        local.get 4
        local.get 10
        i32.add
        local.tee 1
        i32.const 32
        i32.add
        local.tee 2
        call 4
        local.get 2
        local.get 2
        i32.load
        i32.const -1
        i32.xor
        i32.store
        local.get 1
        i32.const 36
        i32.add
        local.tee 2
        local.get 2
        i32.load
        i32.const -1
        i32.xor
        i32.store
        local.get 1
        i32.const 52
        i32.add
        local.tee 2
        local.get 2
        i32.load
        i32.const -1
        i32.xor
        i32.store
        local.get 1
        i32.const 56
        i32.add
        local.tee 1
        local.get 1
        i32.load
        i32.const -1
        i32.xor
        i32.store
        local.get 4
        local.get 6
        i32.add
        local.set 1
        block  ;; label = @3
          local.get 9
          i32.const 8
          i32.ge_u
          if  ;; label = @4
            local.get 1
            local.get 1
            i32.load
            i32.const 49152
            i32.xor
            i32.store
            local.get 1
            i32.const 4
            i32.add
            local.tee 2
            local.get 2
            i32.load
            i32.const 49152
            i32.xor
            i32.store
            local.get 1
            i32.const 12
            i32.add
            local.tee 2
            local.get 2
            i32.load
            i32.const 49152
            i32.xor
            i32.store
            local.get 1
            i32.const 16
            i32.add
            local.tee 1
            local.get 1
            i32.load
            i32.const 49152
            i32.xor
            i32.store
            br 1 (;@3;)
          end
          local.get 1
          i32.const 32
          i32.add
          local.tee 1
          local.get 1
          i32.load
          i32.const 49152
          i32.xor
          i32.store
        end
        i32.const 0
        local.set 2
        i32.const -8
        local.set 3
        local.get 4
        local.get 0
        i32.const 2
        i32.shl
        i32.add
        local.set 1
        i32.const 88
        local.get 0
        local.get 0
        i32.const 88
        i32.ge_u
        select
        i32.const 88
        i32.sub
        local.set 15
        block  ;; label = @3
          block  ;; label = @4
            block  ;; label = @5
              loop  ;; label = @6
                local.get 0
                local.get 3
                i32.add
                local.tee 7
                i32.const 88
                i32.ge_u
                br_if 2 (;@4;)
                local.get 2
                local.get 15
                i32.eq
                br_if 1 (;@5;)
                local.get 1
                local.get 1
                i32.const 32
                i32.sub
                i32.load
                local.get 1
                i32.load
                i32.const 14
                i32.rotr
                i32.const 50529027
                i32.and
                i32.xor
                local.tee 7
                i32.const 2
                i32.shl
                i32.const -50529028
                i32.and
                local.get 7
                i32.const 4
                i32.shl
                i32.const -252645136
                i32.and
                i32.xor
                local.get 7
                i32.const 6
                i32.shl
                i32.const -1061109568
                i32.and
                i32.xor
                local.get 7
                i32.xor
                i32.store
                local.get 3
                i32.const 1
                i32.add
                local.set 3
                local.get 1
                i32.const 4
                i32.add
                local.set 1
                local.get 2
                i32.const 1
                i32.sub
                local.tee 2
                i32.const -8
                i32.ne
                br_if 0 (;@6;)
              end
              br 2 (;@3;)
            end
            local.get 0
            local.get 2
            i32.sub
            i32.const 1048960
            call 19
            unreachable
          end
          local.get 7
          i32.const 1048944
          call 19
          unreachable
        end
        local.get 9
        i32.const 1
        i32.add
        local.set 9
        local.get 6
        i32.const 36
        i32.add
        local.set 6
        local.get 0
        i32.const 8
        i32.add
        local.set 0
        local.get 10
        i32.const 32
        i32.add
        local.tee 10
        i32.const 320
        i32.ne
        br_if 0 (;@2;)
      end
      local.get 4
      i32.const 96
      i32.add
      local.set 6
      local.get 4
      i32.const -64
      i32.sub
      local.set 10
      local.get 4
      i32.const 32
      i32.add
      local.set 9
      i32.const 0
      local.set 0
      loop  ;; label = @2
        local.get 0
        i32.const 0
        local.set 0
        loop  ;; label = @3
          local.get 0
          local.get 9
          i32.add
          local.tee 2
          local.get 2
          i32.load
          local.tee 2
          local.get 2
          local.get 2
          i32.const 4
          i32.shr_u
          i32.xor
          i32.const 51317760
          i32.and
          local.tee 2
          i32.const 4
          i32.shl
          i32.xor
          local.get 2
          i32.xor
          local.tee 2
          local.get 2
          local.get 2
          i32.const 2
          i32.shr_u
          i32.xor
          i32.const 855651072
          i32.and
          local.tee 2
          i32.const 2
          i32.shl
          i32.xor
          local.get 2
          i32.xor
          i32.store
          local.get 0
          i32.const 4
          i32.add
          local.tee 0
          i32.const 32
          i32.ne
          br_if 0 (;@3;)
        end
        i32.const 0
        local.set 0
        loop  ;; label = @3
          local.get 0
          local.get 10
          i32.add
          local.tee 2
          local.get 2
          i32.load
          local.tee 2
          local.get 2
          local.get 2
          i32.const 4
          i32.shr_u
          i32.xor
          i32.const 251662080
          i32.and
          local.tee 2
          i32.const 4
          i32.shl
          i32.xor
          local.get 2
          i32.xor
          i32.store
          local.get 0
          i32.const 4
          i32.add
          local.tee 0
          i32.const 32
          i32.ne
          br_if 0 (;@3;)
        end
        i32.const 0
        local.set 0
        loop  ;; label = @3
          local.get 0
          local.get 6
          i32.add
          local.tee 2
          local.get 2
          i32.load
          local.tee 2
          local.get 2
          local.get 2
          i32.const 4
          i32.shr_u
          i32.xor
          i32.const 202310400
          i32.and
          local.tee 2
          i32.const 4
          i32.shl
          i32.xor
          local.get 2
          i32.xor
          local.tee 2
          local.get 2
          local.get 2
          i32.const 2
          i32.shr_u
          i32.xor
          i32.const 855651072
          i32.and
          local.tee 2
          i32.const 2
          i32.shl
          i32.xor
          local.get 2
          i32.xor
          i32.store
          local.get 0
          i32.const 4
          i32.add
          local.tee 0
          i32.const 32
          i32.ne
          br_if 0 (;@3;)
        end
        local.get 6
        i32.const 128
        i32.add
        local.set 6
        local.get 10
        i32.const 128
        i32.add
        local.set 10
        local.get 9
        i32.const 128
        i32.add
        local.set 9
        i32.const 1
        local.set 0
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
      end
      i32.const 288
      local.set 0
      loop  ;; label = @2
        local.get 0
        local.get 4
        i32.add
        local.tee 1
        local.get 1
        i32.load
        local.tee 1
        local.get 1
        local.get 1
        i32.const 4
        i32.shr_u
        i32.xor
        i32.const 51317760
        i32.and
        local.tee 1
        i32.const 4
        i32.shl
        i32.xor
        local.get 1
        i32.xor
        local.tee 1
        local.get 1
        local.get 1
        i32.const 2
        i32.shr_u
        i32.xor
        i32.const 855651072
        i32.and
        local.tee 1
        i32.const 2
        i32.shl
        i32.xor
        local.get 1
        i32.xor
        i32.store
        local.get 0
        i32.const 4
        i32.add
        local.tee 0
        i32.const 320
        i32.ne
        br_if 0 (;@2;)
      end
      i32.const 0
      local.set 0
      loop  ;; label = @2
        local.get 0
        local.get 4
        i32.add
        local.tee 1
        i32.const 32
        i32.add
        local.tee 2
        local.get 2
        i32.load
        i32.const -1
        i32.xor
        i32.store
        local.get 1
        i32.const 36
        i32.add
        local.tee 2
        local.get 2
        i32.load
        i32.const -1
        i32.xor
        i32.store
        local.get 1
        i32.const 52
        i32.add
        local.tee 2
        local.get 2
        i32.load
        i32.const -1
        i32.xor
        i32.store
        local.get 1
        i32.const 56
        i32.add
        local.tee 1
        local.get 1
        i32.load
        i32.const -1
        i32.xor
        i32.store
        local.get 0
        i32.const 32
        i32.add
        local.tee 0
        i32.const 320
        i32.ne
        br_if 0 (;@2;)
      end
      local.get 8
      local.get 4
      i32.const 352
      memory.copy
      local.get 4
      i32.const 352
      i32.add
      global.set 0
      local.get 5
      i64.const 6869194837183520599
      i64.store offset=808
      local.get 5
      i64.const 5210488070931961695
      i64.store offset=800
      local.get 5
      i64.const 0
      i64.store offset=792
      local.get 5
      i64.const 0
      i64.store offset=784
      local.get 5
      i32.const 384
      i32.add
      local.tee 15
      call 36
      local.get 5
      local.get 8
      i32.const 384
      memory.copy
      local.get 5
      i32.const 0
      i32.store8 offset=400
      local.get 8
      block (result i32)  ;; label = @2
        block  ;; label = @3
          local.get 11
          i64.extend_i32_u
          local.tee 30
          i64.const 32
          i64.shr_u
          i64.eqz
          if  ;; label = @4
            local.get 30
            i32.wrap_i64
            local.tee 0
            i32.const 2147483647
            i32.le_u
            br_if 1 (;@3;)
          end
          local.get 8
          i32.const 0
          i32.store offset=4
          i32.const 1
          br 1 (;@2;)
        end
        local.get 0
        i32.eqz
        if  ;; label = @3
          local.get 8
          i32.const 1
          i32.store offset=8
          local.get 8
          i32.const 0
          i32.store offset=4
          i32.const 0
          br 1 (;@2;)
        end
        i32.const 1050233
        i32.load8_u
        drop
        local.get 0
        i32.const 1
        call 39
        local.tee 1
        if  ;; label = @3
          local.get 8
          local.get 1
          i32.store offset=8
          local.get 8
          local.get 11
          i32.store offset=4
          i32.const 0
          br 1 (;@2;)
        end
        local.get 8
        local.get 0
        i32.store offset=8
        local.get 8
        i32.const 1
        i32.store offset=4
        i32.const 1
      end
      i32.store
      local.get 5
      i32.load offset=436
      local.set 24
      block  ;; label = @2
        block  ;; label = @3
          local.get 5
          i32.load offset=432
          i32.const 1
          i32.ne
          if  ;; label = @4
            local.get 5
            i32.load offset=440
            local.set 18
            local.get 11
            if  ;; label = @5
              local.get 18
              local.get 13
              local.get 11
              memory.copy
            end
            block  ;; label = @5
              local.get 5
              i64.load offset=360
              i64.const -1
              i64.eq
              local.get 5
              i64.load offset=352
              local.tee 30
              i64.const -4294967297
              i64.gt_u
              i32.and
              i32.eqz
              if  ;; label = @6
                local.get 11
                i32.const 15
                i32.and
                local.set 19
                local.get 11
                i32.const 4
                i32.shr_u
                local.set 4
                br 1 (;@5;)
              end
              local.get 11
              i32.const 4
              i32.shr_u
              local.tee 4
              local.get 11
              i32.const 15
              i32.and
              local.tee 19
              i32.const 0
              i32.ne
              i32.add
              local.get 30
              i32.wrap_i64
              i32.const -1
              i32.xor
              i32.gt_u
              br_if 2 (;@3;)
            end
            local.get 5
            local.get 4
            i32.store offset=444
            local.get 5
            local.get 18
            i32.store offset=440
            local.get 5
            local.get 18
            i32.store offset=436
            local.get 5
            local.get 5
            i32.const 352
            i32.add
            local.tee 13
            i32.store offset=432
            global.get 0
            i32.const 176
            i32.sub
            local.tee 3
            global.set 0
            local.get 5
            i32.const 432
            i32.add
            local.tee 0
            i32.load offset=12
            local.tee 22
            i32.const 1
            i32.and
            local.get 0
            i32.load offset=8
            local.set 25
            local.get 0
            i32.load offset=4
            local.set 26
            local.get 0
            i32.load
            local.set 7
            local.get 22
            i32.const 2
            i32.ge_u
            if  ;; label = @5
              local.get 22
              i32.const 1
              i32.shr_u
              local.set 28
              local.get 3
              i32.const -64
              i32.sub
              local.set 2
              local.get 3
              i32.const 128
              i32.add
              local.set 9
              local.get 3
              i32.const 96
              i32.add
              local.set 10
              loop  ;; label = @6
                local.get 3
                i32.const 80
                i32.add
                call 29
                local.get 3
                i32.const 112
                i32.add
                call 29
                i32.const 0
                local.set 6
                loop  ;; label = @7
                  local.get 3
                  call 36
                  local.get 3
                  i32.const 152
                  i32.add
                  local.get 7
                  i64.load offset=16
                  local.tee 32
                  local.get 7
                  i64.load
                  local.tee 33
                  i64.add
                  local.tee 30
                  i64.const 56
                  i64.shl
                  local.get 30
                  i64.const 65280
                  i64.and
                  i64.const 40
                  i64.shl
                  i64.or
                  local.get 30
                  i64.const 16711680
                  i64.and
                  i64.const 24
                  i64.shl
                  local.get 30
                  i64.const 4278190080
                  i64.and
                  i64.const 8
                  i64.shl
                  i64.or
                  i64.or
                  local.get 30
                  i64.const 8
                  i64.shr_u
                  i64.const 4278190080
                  i64.and
                  local.get 30
                  i64.const 24
                  i64.shr_u
                  i64.const 16711680
                  i64.and
                  i64.or
                  local.get 30
                  i64.const 40
                  i64.shr_u
                  i64.const 65280
                  i64.and
                  local.get 30
                  i64.const 56
                  i64.shr_u
                  i64.or
                  i64.or
                  i64.or
                  local.tee 31
                  i64.store
                  local.get 3
                  local.get 31
                  i64.store offset=8
                  local.get 3
                  local.get 30
                  local.get 32
                  i64.lt_u
                  i64.extend_i32_u
                  local.get 7
                  i64.load offset=8
                  local.tee 32
                  local.get 7
                  i64.load offset=24
                  i64.add
                  i64.add
                  local.tee 30
                  i64.const 56
                  i64.shl
                  local.get 30
                  i64.const 65280
                  i64.and
                  i64.const 40
                  i64.shl
                  i64.or
                  local.get 30
                  i64.const 16711680
                  i64.and
                  i64.const 24
                  i64.shl
                  local.get 30
                  i64.const 4278190080
                  i64.and
                  i64.const 8
                  i64.shl
                  i64.or
                  i64.or
                  local.get 30
                  i64.const 8
                  i64.shr_u
                  i64.const 4278190080
                  i64.and
                  local.get 30
                  i64.const 24
                  i64.shr_u
                  i64.const 16711680
                  i64.and
                  i64.or
                  local.get 30
                  i64.const 40
                  i64.shr_u
                  i64.const 65280
                  i64.and
                  local.get 30
                  i64.const 56
                  i64.shr_u
                  i64.or
                  i64.or
                  i64.or
                  local.tee 30
                  i64.store
                  local.get 3
                  local.get 30
                  i64.store offset=144
                  local.get 7
                  local.get 32
                  local.get 33
                  i64.const 1
                  i64.add
                  local.tee 33
                  i64.eqz
                  i64.extend_i32_u
                  i64.add
                  i64.store offset=8
                  local.get 7
                  local.get 33
                  i64.store
                  local.get 3
                  i32.const 112
                  i32.add
                  local.tee 4
                  local.get 6
                  i32.add
                  local.tee 0
                  i32.const 8
                  i32.add
                  local.get 31
                  i64.store align=1
                  local.get 0
                  local.get 30
                  i64.store align=1
                  local.get 6
                  i32.const 16
                  i32.add
                  local.tee 6
                  i32.const 32
                  i32.ne
                  br_if 0 (;@7;)
                end
                local.get 3
                i32.const 80
                i32.add
                local.tee 0
                local.get 5
                local.get 4
                call 6
                local.get 3
                i32.const 136
                i32.add
                local.get 26
                local.get 21
                i32.const 5
                i32.shl
                local.tee 29
                i32.add
                local.tee 1
                i32.const 24
                i32.add
                i64.load align=1
                i64.store
                local.get 3
                i32.const 128
                i32.add
                local.get 1
                i32.const 16
                i32.add
                i64.load align=1
                i64.store
                local.get 3
                i32.const 120
                i32.add
                local.get 1
                i32.const 8
                i32.add
                i64.load align=1
                i64.store
                local.get 3
                local.get 1
                i64.load align=1
                i64.store offset=112
                local.get 3
                i32.const 48
                i32.add
                local.tee 1
                call 29
                i32.const 1
                local.set 8
                loop  ;; label = @7
                  i32.const 0
                  local.set 6
                  loop  ;; label = @8
                    local.get 1
                    local.get 6
                    i32.add
                    local.get 0
                    local.get 6
                    i32.add
                    i32.load8_u
                    local.get 4
                    local.get 6
                    i32.add
                    i32.load8_u
                    i32.xor
                    i32.store8
                    local.get 6
                    i32.const 1
                    i32.add
                    local.tee 6
                    i32.const 16
                    i32.ne
                    br_if 0 (;@8;)
                  end
                  local.get 8
                  i32.const 0
                  local.set 8
                  local.get 10
                  local.set 0
                  local.get 9
                  local.set 4
                  local.get 2
                  local.set 1
                  br_if 0 (;@7;)
                end
                local.get 25
                local.get 29
                i32.add
                local.tee 0
                local.get 3
                i64.load offset=48 align=1
                i64.store align=1
                local.get 0
                i32.const 24
                i32.add
                local.get 3
                i32.const 72
                i32.add
                i64.load align=1
                i64.store align=1
                local.get 0
                i32.const 16
                i32.add
                local.get 3
                i32.const -64
                i32.sub
                i64.load align=1
                i64.store align=1
                local.get 0
                i32.const 8
                i32.add
                local.get 3
                i32.const 56
                i32.add
                i64.load align=1
                i64.store align=1
                local.get 28
                local.get 21
                i32.const 1
                i32.add
                local.tee 21
                i32.ne
                br_if 0 (;@6;)
              end
            end
            local.get 3
            call 29
            if  ;; label = @5
              local.get 25
              local.get 22
              i32.const 268435454
              i32.and
              i32.const 4
              i32.shl
              local.tee 1
              i32.add
              local.set 0
              local.get 3
              i32.const 160
              i32.add
              call 36
              local.get 7
              local.get 7
              i64.load
              local.tee 30
              i64.const 1
              i64.add
              local.tee 31
              i64.store
              local.get 7
              local.get 7
              i64.load offset=8
              local.tee 32
              local.get 31
              i64.eqz
              i64.extend_i32_u
              i64.add
              i64.store offset=8
              local.get 3
              local.get 30
              local.get 7
              i64.load offset=16
              local.tee 31
              i64.add
              local.tee 30
              i64.const 56
              i64.shl
              local.get 30
              i64.const 65280
              i64.and
              i64.const 40
              i64.shl
              i64.or
              local.get 30
              i64.const 16711680
              i64.and
              i64.const 24
              i64.shl
              local.get 30
              i64.const 4278190080
              i64.and
              i64.const 8
              i64.shl
              i64.or
              i64.or
              local.get 30
              i64.const 8
              i64.shr_u
              i64.const 4278190080
              i64.and
              local.get 30
              i64.const 24
              i64.shr_u
              i64.const 16711680
              i64.and
              i64.or
              local.get 30
              i64.const 40
              i64.shr_u
              i64.const 65280
              i64.and
              local.get 30
              i64.const 56
              i64.shr_u
              i64.or
              i64.or
              i64.or
              i64.store offset=168
              local.get 3
              local.get 30
              local.get 31
              i64.lt_u
              i64.extend_i32_u
              local.get 32
              local.get 7
              i64.load offset=24
              i64.add
              i64.add
              local.tee 30
              i64.const 56
              i64.shl
              local.get 30
              i64.const 65280
              i64.and
              i64.const 40
              i64.shl
              i64.or
              local.get 30
              i64.const 16711680
              i64.and
              i64.const 24
              i64.shl
              local.get 30
              i64.const 4278190080
              i64.and
              i64.const 8
              i64.shl
              i64.or
              i64.or
              local.get 30
              i64.const 8
              i64.shr_u
              i64.const 4278190080
              i64.and
              local.get 30
              i64.const 24
              i64.shr_u
              i64.const 16711680
              i64.and
              i64.or
              local.get 30
              i64.const 40
              i64.shr_u
              i64.const 65280
              i64.and
              local.get 30
              i64.const 56
              i64.shr_u
              i64.or
              i64.or
              i64.or
              i64.store offset=160
              local.get 3
              i32.const 80
              i32.add
              local.tee 4
              call 29
              local.get 3
              i32.const 88
              i32.add
              local.get 3
              i64.load offset=168
              i64.store
              local.get 3
              local.get 3
              i64.load offset=160
              i64.store offset=80
              local.get 3
              i32.const 112
              i32.add
              local.get 5
              local.get 4
              call 6
              local.get 3
              i32.const 8
              i32.add
              local.get 3
              i32.const 120
              i32.add
              local.tee 4
              i64.load align=1
              i64.store
              local.get 3
              local.get 3
              i64.load offset=112 align=1
              i64.store
              local.get 4
              local.get 1
              local.get 26
              i32.add
              local.tee 1
              i32.const 8
              i32.add
              i64.load align=1
              i64.store
              local.get 3
              local.get 1
              i64.load align=1
              i64.store offset=112
              local.get 3
              i32.const 32
              i32.add
              call 36
              i32.const 0
              local.set 6
              loop  ;; label = @6
                local.get 3
                i32.const 32
                i32.add
                local.get 6
                i32.add
                local.get 3
                local.get 6
                i32.add
                i32.load8_u
                local.get 3
                i32.const 112
                i32.add
                local.get 6
                i32.add
                i32.load8_u
                i32.xor
                i32.store8
                local.get 6
                i32.const 1
                i32.add
                local.tee 6
                i32.const 16
                i32.ne
                br_if 0 (;@6;)
              end
              local.get 0
              local.get 3
              i64.load offset=32 align=1
              i64.store align=1
              local.get 0
              i32.const 8
              i32.add
              local.get 3
              i32.const 40
              i32.add
              i64.load align=1
              i64.store align=1
            end
            local.get 3
            i32.const 176
            i32.add
            global.set 0
            local.get 19
            if  ;; label = @5
              local.get 18
              local.get 11
              i32.const -16
              i32.and
              i32.add
              local.set 4
              global.get 0
              i32.const 80
              i32.sub
              local.tee 0
              global.set 0
              local.get 0
              i32.const -64
              i32.sub
              call 36
              local.get 13
              local.get 13
              i64.load
              local.tee 30
              i64.const 1
              i64.add
              local.tee 31
              i64.store
              local.get 13
              local.get 13
              i64.load offset=8
              local.tee 32
              local.get 31
              i64.eqz
              i64.extend_i32_u
              i64.add
              i64.store offset=8
              local.get 0
              local.get 30
              local.get 13
              i64.load offset=16
              local.tee 31
              i64.add
              local.tee 30
              i64.const 56
              i64.shl
              local.get 30
              i64.const 65280
              i64.and
              i64.const 40
              i64.shl
              i64.or
              local.get 30
              i64.const 16711680
              i64.and
              i64.const 24
              i64.shl
              local.get 30
              i64.const 4278190080
              i64.and
              i64.const 8
              i64.shl
              i64.or
              i64.or
              local.get 30
              i64.const 8
              i64.shr_u
              i64.const 4278190080
              i64.and
              local.get 30
              i64.const 24
              i64.shr_u
              i64.const 16711680
              i64.and
              i64.or
              local.get 30
              i64.const 40
              i64.shr_u
              i64.const 65280
              i64.and
              local.get 30
              i64.const 56
              i64.shr_u
              i64.or
              i64.or
              i64.or
              i64.store offset=72
              local.get 0
              local.get 30
              local.get 31
              i64.lt_u
              i64.extend_i32_u
              local.get 32
              local.get 13
              i64.load offset=24
              i64.add
              i64.add
              local.tee 30
              i64.const 56
              i64.shl
              local.get 30
              i64.const 65280
              i64.and
              i64.const 40
              i64.shl
              i64.or
              local.get 30
              i64.const 16711680
              i64.and
              i64.const 24
              i64.shl
              local.get 30
              i64.const 4278190080
              i64.and
              i64.const 8
              i64.shl
              i64.or
              i64.or
              local.get 30
              i64.const 8
              i64.shr_u
              i64.const 4278190080
              i64.and
              local.get 30
              i64.const 24
              i64.shr_u
              i64.const 16711680
              i64.and
              i64.or
              local.get 30
              i64.const 40
              i64.shr_u
              i64.const 65280
              i64.and
              local.get 30
              i64.const 56
              i64.shr_u
              i64.or
              i64.or
              i64.or
              i64.store offset=64
              local.get 0
              call 29
              local.get 0
              i32.const 8
              i32.add
              local.get 0
              i64.load offset=72
              i64.store
              local.get 0
              local.get 0
              i64.load offset=64
              i64.store
              local.get 0
              i32.const 32
              i32.add
              local.get 5
              local.get 0
              call 6
              local.get 15
              i32.const 8
              i32.add
              local.get 0
              i32.const 40
              i32.add
              i64.load align=1
              i64.store align=1
              local.get 15
              local.get 0
              i64.load offset=32 align=1
              i64.store align=1
              local.get 0
              i32.const 80
              i32.add
              global.set 0
              loop  ;; label = @6
                local.get 4
                local.get 15
                i32.load8_u
                local.get 4
                i32.load8_u
                i32.xor
                i32.store8
                local.get 4
                i32.const 1
                i32.add
                local.set 4
                local.get 15
                i32.const 1
                i32.add
                local.set 15
                local.get 19
                i32.const 1
                i32.sub
                local.tee 19
                br_if 0 (;@6;)
              end
            end
            local.get 20
            local.get 11
            i32.store offset=8
            local.get 20
            local.get 18
            i32.store offset=4
            local.get 20
            local.get 24
            i32.store
            local.get 5
            i32.const 816
            i32.add
            global.set 0
            br 2 (;@2;)
          end
          local.get 24
          local.get 5
          i32.load offset=440
          i32.const 1048812
          call 32
          unreachable
        end
        global.get 0
        i32.const -64
        i32.add
        local.tee 0
        global.set 0
        local.get 0
        i32.const 43
        i32.store offset=12
        local.get 0
        i32.const 1048592
        i32.store offset=8
        local.get 0
        i32.const 1048576
        i32.store offset=20
        local.get 0
        local.get 5
        i32.const 432
        i32.add
        i32.store offset=16
        local.get 0
        i32.const 2
        i32.store offset=28
        local.get 0
        i32.const 1050188
        i32.store offset=24
        local.get 0
        i64.const 2
        i64.store offset=36 align=4
        local.get 0
        local.get 0
        i32.const 16
        i32.add
        i64.extend_i32_u
        i64.const 85899345920
        i64.or
        i64.store offset=56
        local.get 0
        local.get 0
        i32.const 8
        i32.add
        i64.extend_i32_u
        i64.const 90194313216
        i64.or
        i64.store offset=48
        local.get 0
        local.get 0
        i32.const 48
        i32.add
        i32.store offset=32
        local.get 0
        i32.const 24
        i32.add
        i32.const 1048728
        call 28
        unreachable
      end
      i32.const 1050233
      i32.load8_u
      drop
      i32.const 56
      i32.const 1
      call 39
      local.tee 1
      if  ;; label = @2
        local.get 1
        i64.const 143009642011427521
        i64.store offset=48 align=1
        local.get 1
        i64.const 6315395457821302550
        i64.store offset=40 align=1
        local.get 1
        i64.const -1955905064672638357
        i64.store offset=32 align=1
        local.get 1
        i64.const -8684071750392024005
        i64.store offset=24 align=1
        local.get 1
        i64.const -8682618338371224816
        i64.store offset=16 align=1
        local.get 1
        i64.const 2570840801305670777
        i64.store offset=8 align=1
        local.get 1
        i64.const 3584201232957687288
        i64.store align=1
        local.get 12
        i32.const 56
        i32.store offset=20
        local.get 12
        local.get 1
        i32.store offset=24
        local.get 12
        i32.const 56
        i32.store offset=28
        local.get 12
        i32.load offset=16
        i32.const 56
        i32.eq
        if  ;; label = @3
          local.get 12
          i32.load offset=12
          local.set 14
          i32.const 56
          local.set 0
          block  ;; label = @4
            loop  ;; label = @5
              local.get 14
              i32.load8_u
              local.tee 4
              local.get 1
              i32.load8_u
              local.tee 8
              i32.eq
              if  ;; label = @6
                local.get 14
                i32.const 1
                i32.add
                local.set 14
                local.get 1
                i32.const 1
                i32.add
                local.set 1
                local.get 0
                i32.const 1
                i32.sub
                local.tee 0
                br_if 1 (;@5;)
                br 2 (;@4;)
              end
            end
            local.get 4
            local.get 8
            i32.sub
            local.set 23
          end
          local.get 23
          i32.eqz
          local.set 14
        end
        local.get 12
        i32.const 20
        i32.add
        call 18
        local.get 12
        i32.const 8
        i32.add
        call 18
        local.get 17
        call 18
        local.get 12
        i32.const 32
        i32.add
        global.set 0
        local.get 14
        br 1 (;@1;)
      end
      i32.const 1
      i32.const 56
      call 50
      unreachable
    end
    local.get 16
    i32.const 32
    i32.add
    global.set 0)
  (func (;24;) (type 1) (param i32 i32)
    (local i32)
    global.get 0
    i32.const 32
    i32.sub
    local.tee 2
    global.set 0
    local.get 2
    i32.const 0
    i32.store offset=16
    local.get 2
    i32.const 1
    i32.store offset=4
    local.get 2
    i64.const 4
    i64.store offset=8 align=4
    local.get 2
    i32.const 46
    i32.store offset=28
    local.get 2
    local.get 0
    i32.store offset=24
    local.get 2
    local.get 2
    i32.const 24
    i32.add
    i32.store
    local.get 2
    local.get 1
    call 28
    unreachable)
  (func (;25;) (type 0) (param i32 i32) (result i32)
    block  ;; label = @1
      local.get 1
      i32.eqz
      local.get 0
      local.get 1
      call 33
      i32.eqz
      i32.or
      br_if 0 (;@1;)
      local.get 0
      if  ;; label = @2
        i32.const 1050233
        i32.load8_u
        drop
        local.get 0
        local.get 1
        call 39
        local.tee 1
        i32.eqz
        br_if 1 (;@1;)
      end
      local.get 1
      return
    end
    unreachable)
  (func (;26;) (type 5) (param i32 i32 i32 i32) (result i32)
    block  ;; label = @1
      local.get 2
      i32.const 1114112
      i32.eq
      br_if 0 (;@1;)
      local.get 0
      local.get 2
      local.get 1
      i32.load offset=16
      call_indirect (type 0)
      i32.eqz
      br_if 0 (;@1;)
      i32.const 1
      return
    end
    local.get 3
    i32.eqz
    if  ;; label = @1
      i32.const 0
      return
    end
    local.get 0
    local.get 3
    i32.const 0
    local.get 1
    i32.load offset=12
    call_indirect (type 2))
  (func (;27;) (type 5) (param i32 i32 i32 i32) (result i32)
    block  ;; label = @1
      local.get 3
      i32.eqz
      local.get 1
      local.get 3
      call 33
      i32.eqz
      i32.or
      br_if 0 (;@1;)
      local.get 0
      local.get 1
      local.get 3
      local.get 2
      call 35
      local.tee 0
      i32.eqz
      br_if 0 (;@1;)
      local.get 0
      return
    end
    unreachable)
  (func (;28;) (type 1) (param i32 i32)
    (local i32 i32 i64)
    global.get 0
    i32.const 16
    i32.sub
    local.tee 2
    global.set 0
    local.get 2
    i32.const 1
    i32.store16 offset=12
    local.get 2
    local.get 1
    i32.store offset=8
    local.get 2
    local.get 0
    i32.store offset=4
    global.get 0
    i32.const 16
    i32.sub
    local.tee 1
    global.set 0
    local.get 2
    i32.const 4
    i32.add
    local.tee 0
    i64.load align=4
    local.set 4
    local.get 1
    local.get 0
    i32.store offset=12
    local.get 1
    local.get 4
    i64.store offset=4 align=4
    global.get 0
    i32.const 16
    i32.sub
    local.tee 0
    global.set 0
    local.get 1
    i32.const 4
    i32.add
    local.tee 1
    i32.load
    local.tee 2
    i32.load offset=12
    local.set 3
    block  ;; label = @1
      block  ;; label = @2
        block  ;; label = @3
          block  ;; label = @4
            local.get 2
            i32.load offset=4
            br_table 0 (;@4;) 1 (;@3;) 2 (;@2;)
          end
          local.get 3
          br_if 1 (;@2;)
          i32.const 1
          local.set 2
          i32.const 0
          local.set 3
          br 2 (;@1;)
        end
        local.get 3
        br_if 0 (;@2;)
        local.get 2
        i32.load
        local.tee 2
        i32.load offset=4
        local.set 3
        local.get 2
        i32.load
        local.set 2
        br 1 (;@1;)
      end
      local.get 0
      i32.const -2147483648
      i32.store
      local.get 0
      local.get 1
      i32.store offset=12
      local.get 0
      i32.const 1049860
      local.get 1
      i32.load offset=4
      local.get 1
      i32.load offset=8
      local.tee 0
      i32.load8_u offset=8
      local.get 0
      i32.load8_u offset=9
      call 14
      unreachable
    end
    local.get 0
    local.get 3
    i32.store offset=4
    local.get 0
    local.get 2
    i32.store
    local.get 0
    i32.const 1049832
    local.get 1
    i32.load offset=4
    local.get 1
    i32.load offset=8
    local.tee 0
    i32.load8_u offset=8
    local.get 0
    i32.load8_u offset=9
    call 14
    unreachable)
  (func (;29;) (type 3) (param i32)
    local.get 0
    i64.const 0
    i64.store align=1
    local.get 0
    i32.const 24
    i32.add
    i64.const 0
    i64.store align=1
    local.get 0
    i32.const 16
    i32.add
    i64.const 0
    i64.store align=1
    local.get 0
    i32.const 8
    i32.add
    i64.const 0
    i64.store align=1)
  (func (;30;) (type 3) (param i32)
    (local i32)
    local.get 0
    i32.load
    local.tee 1
    i32.const -2147483648
    i32.eq
    local.get 1
    i32.eqz
    i32.or
    i32.eqz
    if  ;; label = @1
      local.get 0
      i32.load offset=4
      local.get 1
      call 45
    end)
  (func (;31;) (type 3) (param i32)
    (local i32)
    local.get 0
    i32.load
    local.tee 1
    if  ;; label = @1
      local.get 0
      i32.load offset=4
      local.get 1
      call 45
    end)
  (func (;32;) (type 4) (param i32 i32 i32)
    local.get 0
    if  ;; label = @1
      local.get 0
      local.get 1
      call 50
      unreachable
    end
    global.get 0
    i32.const 32
    i32.sub
    local.tee 0
    global.set 0
    local.get 0
    i32.const 0
    i32.store offset=24
    local.get 0
    i32.const 1
    i32.store offset=12
    local.get 0
    i32.const 1049908
    i32.store offset=8
    local.get 0
    i64.const 4
    i64.store offset=16 align=4
    local.get 0
    i32.const 8
    i32.add
    local.get 2
    call 28
    unreachable)
  (func (;33;) (type 0) (param i32 i32) (result i32)
    local.get 1
    i32.popcnt
    i32.const 1
    i32.eq
    local.get 0
    i32.const -2147483648
    local.get 1
    i32.sub
    i32.le_u
    i32.and)
  (func (;34;) (type 3) (param i32)
    local.get 0
    i32.const 0
    i32.store offset=16
    local.get 0
    i64.const 0
    i64.store offset=8 align=4
    local.get 0
    i64.const 17179869184
    i64.store align=4)
  (func (;35;) (type 5) (param i32 i32 i32 i32) (result i32)
    (local i32 i32 i32 i32 i32)
    block (result i32)  ;; label = @1
      block  ;; label = @2
        block  ;; label = @3
          block  ;; label = @4
            local.get 0
            i32.const 4
            i32.sub
            local.tee 5
            i32.load
            local.tee 4
            i32.const -8
            i32.and
            local.tee 6
            i32.const 4
            i32.const 8
            local.get 4
            i32.const 3
            i32.and
            local.tee 4
            select
            local.get 1
            i32.add
            i32.ge_u
            if  ;; label = @5
              local.get 4
              i32.const 0
              local.get 1
              i32.const 39
              i32.add
              local.tee 4
              local.get 6
              i32.lt_u
              select
              br_if 1 (;@4;)
              block  ;; label = @6
                local.get 2
                i32.const 9
                i32.ge_u
                if  ;; label = @7
                  local.get 2
                  local.get 3
                  call 8
                  local.tee 2
                  br_if 1 (;@6;)
                  i32.const 0
                  br 6 (;@1;)
                end
                block (result i32)  ;; label = @7
                  i32.const 0
                  local.set 1
                  block  ;; label = @8
                    block  ;; label = @9
                      block  ;; label = @10
                        local.get 3
                        i32.const -65588
                        i32.gt_u
                        br_if 0 (;@10;)
                        i32.const 16
                        local.get 3
                        i32.const 11
                        i32.add
                        i32.const -8
                        i32.and
                        local.get 3
                        i32.const 11
                        i32.lt_u
                        select
                        local.set 2
                        local.get 0
                        i32.const 4
                        i32.sub
                        local.tee 5
                        i32.load
                        local.tee 7
                        i32.const -8
                        i32.and
                        local.set 4
                        block  ;; label = @11
                          local.get 7
                          i32.const 3
                          i32.and
                          i32.eqz
                          if  ;; label = @12
                            local.get 2
                            i32.const 256
                            i32.lt_u
                            local.get 4
                            local.get 2
                            i32.const 4
                            i32.or
                            i32.lt_u
                            i32.or
                            local.get 4
                            local.get 2
                            i32.sub
                            i32.const 131073
                            i32.ge_u
                            i32.or
                            br_if 1 (;@11;)
                            local.get 0
                            br 5 (;@7;)
                          end
                          local.get 0
                          i32.const 8
                          i32.sub
                          local.tee 6
                          local.get 4
                          i32.add
                          local.set 8
                          block  ;; label = @12
                            block  ;; label = @13
                              block  ;; label = @14
                                block  ;; label = @15
                                  local.get 2
                                  local.get 4
                                  i32.gt_u
                                  if  ;; label = @16
                                    local.get 8
                                    i32.const 1050704
                                    i32.load
                                    i32.eq
                                    br_if 4 (;@12;)
                                    local.get 8
                                    i32.const 1050700
                                    i32.load
                                    i32.eq
                                    br_if 2 (;@14;)
                                    local.get 8
                                    i32.load offset=4
                                    local.tee 7
                                    i32.const 2
                                    i32.and
                                    br_if 5 (;@11;)
                                    local.get 7
                                    i32.const -8
                                    i32.and
                                    local.tee 7
                                    local.get 4
                                    i32.add
                                    local.tee 4
                                    local.get 2
                                    i32.lt_u
                                    br_if 5 (;@11;)
                                    local.get 8
                                    local.get 7
                                    call 9
                                    local.get 4
                                    local.get 2
                                    i32.sub
                                    local.tee 3
                                    i32.const 16
                                    i32.lt_u
                                    br_if 1 (;@15;)
                                    local.get 5
                                    local.get 2
                                    local.get 5
                                    i32.load
                                    i32.const 1
                                    i32.and
                                    i32.or
                                    i32.const 2
                                    i32.or
                                    i32.store
                                    local.get 2
                                    local.get 6
                                    i32.add
                                    local.tee 1
                                    local.get 3
                                    i32.const 3
                                    i32.or
                                    i32.store offset=4
                                    local.get 4
                                    local.get 6
                                    i32.add
                                    local.tee 2
                                    local.get 2
                                    i32.load offset=4
                                    i32.const 1
                                    i32.or
                                    i32.store offset=4
                                    br 8 (;@8;)
                                  end
                                  local.get 4
                                  local.get 2
                                  i32.sub
                                  local.tee 3
                                  i32.const 15
                                  i32.gt_u
                                  br_if 2 (;@13;)
                                  local.get 0
                                  br 8 (;@7;)
                                end
                                local.get 5
                                local.get 4
                                local.get 5
                                i32.load
                                i32.const 1
                                i32.and
                                i32.or
                                i32.const 2
                                i32.or
                                i32.store
                                local.get 4
                                local.get 6
                                i32.add
                                local.tee 1
                                local.get 1
                                i32.load offset=4
                                i32.const 1
                                i32.or
                                i32.store offset=4
                                local.get 0
                                br 7 (;@7;)
                              end
                              i32.const 1050692
                              i32.load
                              local.get 4
                              i32.add
                              local.tee 4
                              local.get 2
                              i32.lt_u
                              br_if 2 (;@11;)
                              block  ;; label = @14
                                local.get 4
                                local.get 2
                                i32.sub
                                local.tee 3
                                i32.const 15
                                i32.le_u
                                if  ;; label = @15
                                  local.get 5
                                  local.get 7
                                  i32.const 1
                                  i32.and
                                  local.get 4
                                  i32.or
                                  i32.const 2
                                  i32.or
                                  i32.store
                                  local.get 4
                                  local.get 6
                                  i32.add
                                  local.tee 2
                                  local.get 2
                                  i32.load offset=4
                                  i32.const 1
                                  i32.or
                                  i32.store offset=4
                                  i32.const 0
                                  local.set 3
                                  br 1 (;@14;)
                                end
                                local.get 5
                                local.get 2
                                local.get 7
                                i32.const 1
                                i32.and
                                i32.or
                                i32.const 2
                                i32.or
                                i32.store
                                local.get 2
                                local.get 6
                                i32.add
                                local.tee 1
                                local.get 3
                                i32.const 1
                                i32.or
                                i32.store offset=4
                                local.get 4
                                local.get 6
                                i32.add
                                local.tee 2
                                local.get 3
                                i32.store
                                local.get 2
                                local.get 2
                                i32.load offset=4
                                i32.const -2
                                i32.and
                                i32.store offset=4
                              end
                              i32.const 1050700
                              local.get 1
                              i32.store
                              i32.const 1050692
                              local.get 3
                              i32.store
                              local.get 0
                              br 6 (;@7;)
                            end
                            local.get 5
                            local.get 2
                            local.get 7
                            i32.const 1
                            i32.and
                            i32.or
                            i32.const 2
                            i32.or
                            i32.store
                            local.get 2
                            local.get 6
                            i32.add
                            local.tee 1
                            local.get 3
                            i32.const 3
                            i32.or
                            i32.store offset=4
                            local.get 8
                            local.get 8
                            i32.load offset=4
                            i32.const 1
                            i32.or
                            i32.store offset=4
                            br 4 (;@8;)
                          end
                          i32.const 1050696
                          i32.load
                          local.get 4
                          i32.add
                          local.tee 4
                          local.get 2
                          i32.gt_u
                          br_if 2 (;@9;)
                        end
                        local.get 3
                        call 1
                        local.tee 2
                        i32.eqz
                        br_if 0 (;@10;)
                        local.get 3
                        i32.const -4
                        i32.const -8
                        local.get 5
                        i32.load
                        local.tee 1
                        i32.const 3
                        i32.and
                        select
                        local.get 1
                        i32.const -8
                        i32.and
                        i32.add
                        local.tee 1
                        local.get 1
                        local.get 3
                        i32.gt_u
                        select
                        local.tee 1
                        if  ;; label = @11
                          local.get 2
                          local.get 0
                          local.get 1
                          memory.copy
                        end
                        local.get 0
                        call 2
                        local.get 2
                        local.set 1
                      end
                      local.get 1
                      br 2 (;@7;)
                    end
                    local.get 5
                    local.get 2
                    local.get 7
                    i32.const 1
                    i32.and
                    i32.or
                    i32.const 2
                    i32.or
                    i32.store
                    i32.const 1050704
                    local.get 2
                    local.get 6
                    i32.add
                    local.tee 1
                    i32.store
                    i32.const 1050696
                    local.get 4
                    local.get 2
                    i32.sub
                    local.tee 2
                    i32.store
                    local.get 1
                    local.get 2
                    i32.const 1
                    i32.or
                    i32.store offset=4
                    local.get 0
                    br 1 (;@7;)
                  end
                  local.get 1
                  local.get 3
                  call 3
                  local.get 0
                end
                br 5 (;@1;)
              end
              local.get 3
              local.get 1
              local.get 1
              local.get 3
              i32.gt_u
              select
              local.tee 3
              if  ;; label = @6
                local.get 2
                local.get 0
                local.get 3
                memory.copy
              end
              local.get 5
              i32.load
              local.tee 3
              i32.const -8
              i32.and
              local.tee 5
              local.get 1
              i32.const 4
              i32.const 8
              local.get 3
              i32.const 3
              i32.and
              local.tee 3
              select
              i32.add
              i32.lt_u
              br_if 2 (;@3;)
              local.get 3
              i32.const 0
              local.get 4
              local.get 5
              i32.lt_u
              select
              br_if 3 (;@2;)
              local.get 0
              call 2
              local.get 2
              br 4 (;@1;)
            end
            i32.const 1049689
            i32.const 1049736
            call 24
            unreachable
          end
          i32.const 1049752
          i32.const 1049800
          call 24
          unreachable
        end
        i32.const 1049689
        i32.const 1049736
        call 24
        unreachable
      end
      i32.const 1049752
      i32.const 1049800
      call 24
      unreachable
    end)
  (func (;36;) (type 3) (param i32)
    local.get 0
    i64.const 0
    i64.store align=1
    local.get 0
    i32.const 8
    i32.add
    i64.const 0
    i64.store align=1)
  (func (;37;) (type 2) (param i32 i32 i32) (result i32)
    local.get 0
    i32.load
    local.get 1
    local.get 2
    local.get 0
    i32.load offset=4
    i32.load offset=12
    call_indirect (type 2))
  (func (;38;) (type 0) (param i32 i32) (result i32)
    local.get 0
    i32.load
    local.get 1
    local.get 0
    i32.load offset=4
    i32.load offset=12
    call_indirect (type 0))
  (func (;39;) (type 0) (param i32 i32) (result i32)
    block (result i32)  ;; label = @1
      local.get 1
      i32.const 9
      i32.ge_u
      if  ;; label = @2
        local.get 1
        local.get 0
        call 8
        br 1 (;@1;)
      end
      local.get 0
      call 1
    end)
  (func (;40;) (type 1) (param i32 i32)
    local.get 0
    i64.const 7199936582794304877
    i64.store offset=8
    local.get 0
    i64.const -5076933981314334344
    i64.store)
  (func (;41;) (type 1) (param i32 i32)
    local.get 0
    i64.const -7465958581808515274
    i64.store offset=8
    local.get 0
    i64.const -3461089016297083664
    i64.store)
  (func (;42;) (type 0) (param i32 i32) (result i32)
    local.get 1
    local.get 0
    i32.load
    local.get 0
    i32.load offset=4
    call 37)
  (func (;43;) (type 1) (param i32 i32)
    local.get 0
    i32.const 1049816
    i32.store offset=4
    local.get 0
    local.get 1
    i32.store)
  (func (;44;) (type 0) (param i32 i32) (result i32)
    (local i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32)
    local.get 0
    i32.load
    local.set 8
    local.get 0
    i32.load offset=4
    local.set 6
    block  ;; label = @1
      block  ;; label = @2
        local.get 1
        i32.load offset=8
        local.tee 12
        i32.const 402653184
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        block  ;; label = @3
          block  ;; label = @4
            local.get 12
            i32.const 268435456
            i32.and
            i32.eqz
            if  ;; label = @5
              local.get 6
              i32.const 16
              i32.lt_u
              br_if 1 (;@4;)
              block (result i32)  ;; label = @6
                block  ;; label = @7
                  block  ;; label = @8
                    local.get 6
                    local.get 8
                    i32.const 3
                    i32.add
                    i32.const -4
                    i32.and
                    local.tee 0
                    local.get 8
                    i32.sub
                    local.tee 11
                    i32.lt_u
                    br_if 0 (;@8;)
                    local.get 6
                    local.get 11
                    i32.sub
                    local.tee 7
                    i32.const 4
                    i32.lt_u
                    br_if 0 (;@8;)
                    local.get 7
                    i32.const 3
                    i32.and
                    local.set 10
                    block  ;; label = @9
                      local.get 0
                      local.get 8
                      i32.eq
                      local.tee 5
                      br_if 0 (;@9;)
                      local.get 8
                      local.get 0
                      i32.sub
                      local.tee 9
                      i32.const -4
                      i32.le_u
                      if  ;; label = @10
                        loop  ;; label = @11
                          local.get 2
                          local.get 3
                          local.get 8
                          i32.add
                          local.tee 0
                          i32.load8_s
                          i32.const -65
                          i32.gt_s
                          i32.add
                          local.get 0
                          i32.const 1
                          i32.add
                          i32.load8_s
                          i32.const -65
                          i32.gt_s
                          i32.add
                          local.get 0
                          i32.const 2
                          i32.add
                          i32.load8_s
                          i32.const -65
                          i32.gt_s
                          i32.add
                          local.get 0
                          i32.const 3
                          i32.add
                          i32.load8_s
                          i32.const -65
                          i32.gt_s
                          i32.add
                          local.set 2
                          local.get 3
                          i32.const 4
                          i32.add
                          local.tee 3
                          br_if 0 (;@11;)
                        end
                      end
                      local.get 5
                      br_if 0 (;@9;)
                      local.get 3
                      local.get 8
                      i32.add
                      local.set 5
                      loop  ;; label = @10
                        local.get 2
                        local.get 5
                        i32.load8_s
                        i32.const -65
                        i32.gt_s
                        i32.add
                        local.set 2
                        local.get 5
                        i32.const 1
                        i32.add
                        local.set 5
                        local.get 9
                        i32.const 1
                        i32.add
                        local.tee 9
                        br_if 0 (;@10;)
                      end
                    end
                    local.get 8
                    local.get 11
                    i32.add
                    local.set 0
                    block  ;; label = @9
                      local.get 10
                      i32.eqz
                      br_if 0 (;@9;)
                      local.get 0
                      local.get 7
                      i32.const -4
                      i32.and
                      i32.add
                      local.tee 3
                      i32.load8_s
                      i32.const -65
                      i32.gt_s
                      local.set 4
                      local.get 10
                      i32.const 1
                      i32.eq
                      br_if 0 (;@9;)
                      local.get 4
                      local.get 3
                      i32.load8_s offset=1
                      i32.const -65
                      i32.gt_s
                      i32.add
                      local.set 4
                      local.get 10
                      i32.const 2
                      i32.eq
                      br_if 0 (;@9;)
                      local.get 4
                      local.get 3
                      i32.load8_s offset=2
                      i32.const -65
                      i32.gt_s
                      i32.add
                      local.set 4
                    end
                    local.get 7
                    i32.const 2
                    i32.shr_u
                    local.set 9
                    local.get 2
                    local.get 4
                    i32.add
                    local.set 4
                    loop  ;; label = @9
                      local.get 0
                      local.set 7
                      local.get 9
                      i32.eqz
                      br_if 2 (;@7;)
                      i32.const 192
                      local.get 9
                      local.get 9
                      i32.const 192
                      i32.ge_u
                      select
                      local.tee 3
                      i32.const 3
                      i32.and
                      local.set 10
                      local.get 3
                      i32.const 2
                      i32.shl
                      local.set 11
                      i32.const 0
                      local.set 5
                      local.get 9
                      i32.const 4
                      i32.ge_u
                      if  ;; label = @10
                        local.get 0
                        local.get 11
                        i32.const 1008
                        i32.and
                        i32.add
                        local.set 13
                        local.get 0
                        local.set 2
                        loop  ;; label = @11
                          local.get 2
                          i32.load
                          local.tee 0
                          i32.const -1
                          i32.xor
                          i32.const 7
                          i32.shr_u
                          local.get 0
                          i32.const 6
                          i32.shr_u
                          i32.or
                          i32.const 16843009
                          i32.and
                          local.get 5
                          i32.add
                          local.get 2
                          i32.const 4
                          i32.add
                          i32.load
                          local.tee 0
                          i32.const -1
                          i32.xor
                          i32.const 7
                          i32.shr_u
                          local.get 0
                          i32.const 6
                          i32.shr_u
                          i32.or
                          i32.const 16843009
                          i32.and
                          i32.add
                          local.get 2
                          i32.const 8
                          i32.add
                          i32.load
                          local.tee 0
                          i32.const -1
                          i32.xor
                          i32.const 7
                          i32.shr_u
                          local.get 0
                          i32.const 6
                          i32.shr_u
                          i32.or
                          i32.const 16843009
                          i32.and
                          i32.add
                          local.get 2
                          i32.const 12
                          i32.add
                          i32.load
                          local.tee 0
                          i32.const -1
                          i32.xor
                          i32.const 7
                          i32.shr_u
                          local.get 0
                          i32.const 6
                          i32.shr_u
                          i32.or
                          i32.const 16843009
                          i32.and
                          i32.add
                          local.set 5
                          local.get 2
                          i32.const 16
                          i32.add
                          local.tee 2
                          local.get 13
                          i32.ne
                          br_if 0 (;@11;)
                        end
                      end
                      local.get 9
                      local.get 3
                      i32.sub
                      local.set 9
                      local.get 7
                      local.get 11
                      i32.add
                      local.set 0
                      local.get 5
                      i32.const 8
                      i32.shr_u
                      i32.const 16711935
                      i32.and
                      local.get 5
                      i32.const 16711935
                      i32.and
                      i32.add
                      i32.const 65537
                      i32.mul
                      i32.const 16
                      i32.shr_u
                      local.get 4
                      i32.add
                      local.set 4
                      local.get 10
                      i32.eqz
                      br_if 0 (;@9;)
                    end
                    block (result i32)  ;; label = @9
                      local.get 7
                      local.get 3
                      i32.const 252
                      i32.and
                      i32.const 2
                      i32.shl
                      i32.add
                      local.tee 0
                      i32.load
                      local.tee 2
                      i32.const -1
                      i32.xor
                      i32.const 7
                      i32.shr_u
                      local.get 2
                      i32.const 6
                      i32.shr_u
                      i32.or
                      i32.const 16843009
                      i32.and
                      local.tee 2
                      local.get 10
                      i32.const 1
                      i32.eq
                      br_if 0 (;@9;)
                      drop
                      local.get 2
                      local.get 0
                      i32.load offset=4
                      local.tee 7
                      i32.const -1
                      i32.xor
                      i32.const 7
                      i32.shr_u
                      local.get 7
                      i32.const 6
                      i32.shr_u
                      i32.or
                      i32.const 16843009
                      i32.and
                      i32.add
                      local.tee 2
                      local.get 10
                      i32.const 2
                      i32.eq
                      br_if 0 (;@9;)
                      drop
                      local.get 2
                      local.get 0
                      i32.load offset=8
                      local.tee 0
                      i32.const -1
                      i32.xor
                      i32.const 7
                      i32.shr_u
                      local.get 0
                      i32.const 6
                      i32.shr_u
                      i32.or
                      i32.const 16843009
                      i32.and
                      i32.add
                    end
                    local.tee 0
                    i32.const 8
                    i32.shr_u
                    i32.const 459007
                    i32.and
                    local.get 0
                    i32.const 16711935
                    i32.and
                    i32.add
                    i32.const 65537
                    i32.mul
                    i32.const 16
                    i32.shr_u
                    local.get 4
                    i32.add
                    br 2 (;@6;)
                  end
                  i32.const 0
                  local.get 6
                  i32.eqz
                  br_if 1 (;@6;)
                  drop
                  local.get 6
                  i32.const 3
                  i32.and
                  local.set 3
                  local.get 6
                  i32.const 4
                  i32.ge_u
                  if  ;; label = @8
                    local.get 6
                    i32.const -4
                    i32.and
                    local.set 2
                    loop  ;; label = @9
                      local.get 4
                      local.get 5
                      local.get 8
                      i32.add
                      local.tee 0
                      i32.load8_s
                      i32.const -65
                      i32.gt_s
                      i32.add
                      local.get 0
                      i32.const 1
                      i32.add
                      i32.load8_s
                      i32.const -65
                      i32.gt_s
                      i32.add
                      local.get 0
                      i32.const 2
                      i32.add
                      i32.load8_s
                      i32.const -65
                      i32.gt_s
                      i32.add
                      local.get 0
                      i32.const 3
                      i32.add
                      i32.load8_s
                      i32.const -65
                      i32.gt_s
                      i32.add
                      local.set 4
                      local.get 2
                      local.get 5
                      i32.const 4
                      i32.add
                      local.tee 5
                      i32.ne
                      br_if 0 (;@9;)
                    end
                  end
                  local.get 3
                  i32.eqz
                  br_if 0 (;@7;)
                  local.get 5
                  local.get 8
                  i32.add
                  local.set 2
                  loop  ;; label = @8
                    local.get 4
                    local.get 2
                    i32.load8_s
                    i32.const -65
                    i32.gt_s
                    i32.add
                    local.set 4
                    local.get 2
                    i32.const 1
                    i32.add
                    local.set 2
                    local.get 3
                    i32.const 1
                    i32.sub
                    local.tee 3
                    br_if 0 (;@8;)
                  end
                end
                local.get 4
              end
              local.set 3
              br 2 (;@3;)
            end
            block  ;; label = @5
              block  ;; label = @6
                local.get 1
                i32.load16_u offset=14
                local.tee 7
                i32.eqz
                if  ;; label = @7
                  i32.const 0
                  local.set 6
                  br 1 (;@6;)
                end
                local.get 6
                local.get 8
                i32.add
                local.set 5
                i32.const 0
                local.set 6
                local.get 7
                local.set 2
                local.get 8
                local.set 0
                loop  ;; label = @7
                  local.get 0
                  local.tee 3
                  local.get 5
                  i32.eq
                  br_if 2 (;@5;)
                  local.get 6
                  block (result i32)  ;; label = @8
                    local.get 0
                    i32.const 1
                    i32.add
                    local.get 0
                    i32.load8_s
                    local.tee 4
                    i32.const 0
                    i32.ge_s
                    br_if 0 (;@8;)
                    drop
                    local.get 0
                    i32.const 2
                    i32.add
                    local.get 4
                    i32.const -32
                    i32.lt_u
                    br_if 0 (;@8;)
                    drop
                    local.get 0
                    i32.const 3
                    i32.add
                    local.get 4
                    i32.const -16
                    i32.lt_u
                    br_if 0 (;@8;)
                    drop
                    local.get 0
                    i32.const 4
                    i32.add
                  end
                  local.tee 0
                  local.get 3
                  i32.sub
                  i32.add
                  local.set 6
                  local.get 2
                  i32.const 1
                  i32.sub
                  local.tee 2
                  br_if 0 (;@7;)
                end
              end
              i32.const 0
              local.set 2
            end
            local.get 7
            local.get 2
            i32.sub
            local.set 3
            br 1 (;@3;)
          end
          local.get 6
          i32.eqz
          if  ;; label = @4
            i32.const 0
            local.set 6
            br 1 (;@3;)
          end
          local.get 6
          i32.const 3
          i32.and
          local.set 7
          local.get 6
          i32.const 4
          i32.ge_u
          if  ;; label = @4
            local.get 6
            i32.const 12
            i32.and
            local.set 4
            loop  ;; label = @5
              local.get 3
              local.get 2
              local.get 8
              i32.add
              local.tee 0
              i32.load8_s
              i32.const -65
              i32.gt_s
              i32.add
              local.get 0
              i32.const 1
              i32.add
              i32.load8_s
              i32.const -65
              i32.gt_s
              i32.add
              local.get 0
              i32.const 2
              i32.add
              i32.load8_s
              i32.const -65
              i32.gt_s
              i32.add
              local.get 0
              i32.const 3
              i32.add
              i32.load8_s
              i32.const -65
              i32.gt_s
              i32.add
              local.set 3
              local.get 4
              local.get 2
              i32.const 4
              i32.add
              local.tee 2
              i32.ne
              br_if 0 (;@5;)
            end
          end
          local.get 7
          i32.eqz
          br_if 0 (;@3;)
          local.get 2
          local.get 8
          i32.add
          local.set 0
          loop  ;; label = @4
            local.get 3
            local.get 0
            i32.load8_s
            i32.const -65
            i32.gt_s
            i32.add
            local.set 3
            local.get 0
            i32.const 1
            i32.add
            local.set 0
            local.get 7
            i32.const 1
            i32.sub
            local.tee 7
            br_if 0 (;@4;)
          end
        end
        local.get 3
        local.get 1
        i32.load16_u offset=12
        local.tee 0
        i32.ge_u
        br_if 0 (;@2;)
        local.get 0
        local.get 3
        i32.sub
        local.set 7
        i32.const 0
        local.set 3
        i32.const 0
        local.set 2
        block  ;; label = @3
          block  ;; label = @4
            block  ;; label = @5
              local.get 12
              i32.const 29
              i32.shr_u
              i32.const 3
              i32.and
              i32.const 1
              i32.sub
              br_table 0 (;@5;) 1 (;@4;) 2 (;@3;)
            end
            local.get 7
            local.set 2
            br 1 (;@3;)
          end
          local.get 7
          i32.const 65534
          i32.and
          i32.const 1
          i32.shr_u
          local.set 2
        end
        local.get 12
        i32.const 2097151
        i32.and
        local.set 5
        local.get 1
        i32.load offset=4
        local.set 4
        local.get 1
        i32.load
        local.set 1
        loop  ;; label = @3
          local.get 3
          i32.const 65535
          i32.and
          local.get 2
          i32.const 65535
          i32.and
          i32.lt_u
          if  ;; label = @4
            i32.const 1
            local.set 0
            local.get 3
            i32.const 1
            i32.add
            local.set 3
            local.get 1
            local.get 5
            local.get 4
            i32.load offset=16
            call_indirect (type 0)
            i32.eqz
            br_if 1 (;@3;)
            br 3 (;@1;)
          end
        end
        i32.const 1
        local.set 0
        local.get 1
        local.get 8
        local.get 6
        local.get 4
        i32.load offset=12
        call_indirect (type 2)
        br_if 1 (;@1;)
        i32.const 0
        local.set 3
        local.get 7
        local.get 2
        i32.sub
        i32.const 65535
        i32.and
        local.set 2
        loop  ;; label = @3
          local.get 3
          i32.const 65535
          i32.and
          local.tee 8
          local.get 2
          i32.lt_u
          local.set 0
          local.get 2
          local.get 8
          i32.le_u
          br_if 2 (;@1;)
          local.get 3
          i32.const 1
          i32.add
          local.set 3
          local.get 1
          local.get 5
          local.get 4
          i32.load offset=16
          call_indirect (type 0)
          i32.eqz
          br_if 0 (;@3;)
        end
        br 1 (;@1;)
      end
      local.get 1
      i32.load
      local.get 8
      local.get 6
      local.get 1
      i32.load offset=4
      i32.load offset=12
      call_indirect (type 2)
      local.set 0
    end
    local.get 0)
  (func (;45;) (type 1) (param i32 i32)
    (local i32 i32)
    block  ;; label = @1
      block  ;; label = @2
        local.get 0
        i32.const 4
        i32.sub
        i32.load
        local.tee 2
        i32.const -8
        i32.and
        local.tee 3
        i32.const 4
        i32.const 8
        local.get 2
        i32.const 3
        i32.and
        local.tee 2
        select
        local.get 1
        i32.add
        i32.ge_u
        if  ;; label = @3
          local.get 2
          i32.const 0
          local.get 3
          local.get 1
          i32.const 39
          i32.add
          i32.gt_u
          select
          br_if 1 (;@2;)
          local.get 0
          call 2
          br 2 (;@1;)
        end
        i32.const 1049689
        i32.const 1049736
        call 24
        unreachable
      end
      i32.const 1049752
      i32.const 1049800
      call 24
      unreachable
    end)
  (func (;46;) (type 0) (param i32 i32) (result i32)
    (local i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i64)
    local.get 0
    i32.load
    local.set 5
    local.get 1
    local.set 4
    global.get 0
    i32.const 16
    i32.sub
    local.tee 7
    global.set 0
    i32.const 10
    local.set 3
    local.get 5
    local.tee 0
    i32.const 1000
    i32.ge_u
    if  ;; label = @1
      local.get 0
      local.set 1
      loop  ;; label = @2
        local.get 7
        i32.const 6
        i32.add
        local.get 3
        i32.add
        local.tee 2
        i32.const 3
        i32.sub
        local.get 1
        local.get 1
        i32.const 10000
        i32.div_u
        local.tee 0
        i32.const 10000
        i32.mul
        i32.sub
        local.tee 6
        i32.const 65535
        i32.and
        i32.const 100
        i32.div_u
        local.tee 8
        i32.const 1
        i32.shl
        local.tee 9
        i32.const 1049917
        i32.add
        i32.load8_u
        i32.store8
        local.get 2
        i32.const 4
        i32.sub
        local.get 9
        i32.const 1049916
        i32.add
        i32.load8_u
        i32.store8
        local.get 2
        i32.const 1
        i32.sub
        local.get 6
        local.get 8
        i32.const 100
        i32.mul
        i32.sub
        i32.const 65535
        i32.and
        i32.const 1
        i32.shl
        local.tee 6
        i32.const 1049917
        i32.add
        i32.load8_u
        i32.store8
        local.get 2
        i32.const 2
        i32.sub
        local.get 6
        i32.const 1049916
        i32.add
        i32.load8_u
        i32.store8
        local.get 3
        i32.const 4
        i32.sub
        local.set 3
        local.get 1
        i32.const 9999999
        i32.gt_u
        local.get 0
        local.set 1
        br_if 0 (;@2;)
      end
    end
    block  ;; label = @1
      local.get 0
      i32.const 9
      i32.le_u
      if  ;; label = @2
        local.get 0
        local.set 1
        br 1 (;@1;)
      end
      local.get 3
      local.get 7
      i32.add
      i32.const 5
      i32.add
      local.get 0
      local.get 0
      i32.const 65535
      i32.and
      i32.const 100
      i32.div_u
      local.tee 1
      i32.const 100
      i32.mul
      i32.sub
      i32.const 65535
      i32.and
      i32.const 1
      i32.shl
      local.tee 0
      i32.const 1049917
      i32.add
      i32.load8_u
      i32.store8
      local.get 3
      i32.const 2
      i32.sub
      local.tee 3
      local.get 7
      i32.const 6
      i32.add
      i32.add
      local.get 0
      i32.const 1049916
      i32.add
      i32.load8_u
      i32.store8
    end
    i32.const 0
    local.get 5
    local.get 1
    select
    i32.eqz
    if  ;; label = @1
      local.get 3
      i32.const 1
      i32.sub
      local.tee 3
      local.get 7
      i32.const 6
      i32.add
      i32.add
      local.get 1
      i32.const 1
      i32.shl
      i32.const 30
      i32.and
      i32.const 1049917
      i32.add
      i32.load8_u
      i32.store8
    end
    block (result i32)  ;; label = @1
      local.get 7
      i32.const 6
      i32.add
      local.get 3
      i32.add
      local.set 6
      i32.const 0
      local.set 1
      i32.const 43
      i32.const 1114112
      local.get 4
      i32.load offset=8
      local.tee 2
      i32.const 2097152
      i32.and
      local.tee 0
      select
      local.set 8
      local.get 2
      i32.const 8388608
      i32.and
      i32.eqz
      i32.eqz
      local.set 9
      block  ;; label = @2
        i32.const 10
        local.get 3
        i32.sub
        local.tee 11
        local.get 0
        i32.const 21
        i32.shr_u
        i32.add
        local.tee 0
        local.get 4
        i32.load16_u offset=12
        local.tee 5
        i32.lt_u
        if  ;; label = @3
          local.get 2
          i32.const 16777216
          i32.and
          i32.eqz
          if  ;; label = @4
            local.get 5
            local.get 0
            i32.sub
            local.set 5
            i32.const 0
            local.set 0
            block  ;; label = @5
              block  ;; label = @6
                block  ;; label = @7
                  local.get 2
                  i32.const 29
                  i32.shr_u
                  i32.const 3
                  i32.and
                  i32.const 1
                  i32.sub
                  br_table 0 (;@7;) 1 (;@6;) 0 (;@7;) 2 (;@5;)
                end
                local.get 5
                local.set 0
                br 1 (;@5;)
              end
              local.get 5
              i32.const 65534
              i32.and
              i32.const 1
              i32.shr_u
              local.set 0
            end
            local.get 2
            i32.const 2097151
            i32.and
            local.set 10
            local.get 4
            i32.load offset=4
            local.set 2
            local.get 4
            i32.load
            local.set 4
            loop  ;; label = @5
              local.get 1
              i32.const 65535
              i32.and
              local.get 0
              i32.const 65535
              i32.and
              i32.lt_u
              if  ;; label = @6
                i32.const 1
                local.set 3
                local.get 1
                i32.const 1
                i32.add
                local.set 1
                local.get 4
                local.get 10
                local.get 2
                i32.load offset=16
                call_indirect (type 0)
                i32.eqz
                br_if 1 (;@5;)
                br 4 (;@2;)
              end
            end
            i32.const 1
            local.set 3
            local.get 4
            local.get 2
            local.get 8
            local.get 9
            call 26
            br_if 2 (;@2;)
            local.get 4
            local.get 6
            local.get 11
            local.get 2
            i32.load offset=12
            call_indirect (type 2)
            br_if 2 (;@2;)
            i32.const 0
            local.set 1
            local.get 5
            local.get 0
            i32.sub
            i32.const 65535
            i32.and
            local.set 0
            loop  ;; label = @5
              local.get 1
              i32.const 65535
              i32.and
              local.tee 5
              local.get 0
              i32.lt_u
              local.set 3
              local.get 0
              local.get 5
              i32.le_u
              br_if 3 (;@2;)
              local.get 1
              i32.const 1
              i32.add
              local.set 1
              local.get 4
              local.get 10
              local.get 2
              i32.load offset=16
              call_indirect (type 0)
              i32.eqz
              br_if 0 (;@5;)
            end
            br 2 (;@2;)
          end
          local.get 4
          local.get 4
          i64.load offset=8 align=4
          local.tee 12
          i32.wrap_i64
          i32.const -1612709888
          i32.and
          i32.const 536870960
          i32.or
          i32.store offset=8
          i32.const 1
          local.set 3
          local.get 4
          i32.load
          local.tee 2
          local.get 4
          i32.load offset=4
          local.tee 10
          local.get 8
          local.get 9
          call 26
          br_if 1 (;@2;)
          local.get 5
          local.get 0
          i32.sub
          i32.const 65535
          i32.and
          local.set 0
          loop  ;; label = @4
            local.get 0
            local.get 1
            i32.const 65535
            i32.and
            i32.gt_u
            if  ;; label = @5
              local.get 1
              i32.const 1
              i32.add
              local.set 1
              local.get 2
              i32.const 48
              local.get 10
              i32.load offset=16
              call_indirect (type 0)
              i32.eqz
              br_if 1 (;@4;)
              br 3 (;@2;)
            end
          end
          local.get 2
          local.get 6
          local.get 11
          local.get 10
          i32.load offset=12
          call_indirect (type 2)
          br_if 1 (;@2;)
          local.get 4
          local.get 12
          i64.store offset=8 align=4
          i32.const 0
          br 2 (;@1;)
        end
        i32.const 1
        local.set 3
        local.get 4
        i32.load
        local.tee 0
        local.get 4
        i32.load offset=4
        local.tee 1
        local.get 8
        local.get 9
        call 26
        br_if 0 (;@2;)
        local.get 0
        local.get 6
        local.get 11
        local.get 1
        i32.load offset=12
        call_indirect (type 2)
        local.set 3
      end
      local.get 3
    end
    local.get 7
    i32.const 16
    i32.add
    global.set 0)
  (func (;47;) (type 0) (param i32 i32) (result i32)
    local.get 1
    i32.const 1048744
    i32.const 17
    call 37)
  (func (;48;) (type 0) (param i32 i32) (result i32)
    local.get 0
    i32.const 1049572
    local.get 1
    call 5)
  (func (;49;) (type 1) (param i32 i32)
    local.get 0
    local.get 1
    i64.load align=4
    i64.store)
  (func (;50;) (type 1) (param i32 i32)
    local.get 0
    local.get 1
    i32.const 1050248
    i32.load
    local.tee 0
    i32.const 4
    local.get 0
    select
    call_indirect (type 1)
    unreachable)
  (func (;51;) (type 1) (param i32 i32)
    local.get 0
    i32.const 0
    i32.store)
  (table (;0;) 22 22 funcref)
  (table (;1;) 128 externref)
  (memory (;0;) 17)
  (global (;0;) (mut i32) (i32.const 1048576))
  (export "memory" (memory 0))
  (export "check_flag" (func 23))
  (export "__wbindgen_export_0" (table 1))
  (export "__wbindgen_malloc" (func 25))
  (export "__wbindgen_realloc" (func 27))
  (export "__wbindgen_start" (func 0))
  (elem (;0;) (i32.const 1) func 47 34 46 20 31 21 10 48 41 40 42 22 43 49 30 17 13 15 51 38 44)
  (data (;0;) (i32.const 1048584) "\01\00\00\00\01\00\00\00called `Result::unwrap()` on an `Err` value/home/hexular/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/cipher-0.4.4/src/stream.rs;\00\10\00]\00\00\00x\00\00\00'\00\00\00StreamCipherError/build/rustc-1.87.0-src/library/alloc/src/slice.rs\00\b9\00\10\002\00\00\00\be\01\00\00\1d\00\00\00OOOOHMYFAVOURITE/home/hexular/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/aes-0.8.4/src/soft/fixslice32.rs\00\0c\01\10\00c\00\00\00\89\04\00\00\12\00\00\00\0c\01\10\00c\00\00\00\89\04\00\00=\00\00\00\0c\01\10\00c\00\00\00\14\05\00\00\22\00\00\00\0c\01\10\00c\00\00\00\14\05\00\00\09\00\00\00Lazy instance has previously been poisoned\00\00\b0\01\10\00*\00\00\00/home/hexular/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/once_cell-1.21.3/src/lib.rs\00\00\e4\01\10\00^\00\00\00\08\03\00\00\19\00\00\00reentrant init\00\00T\02\10\00\0e\00\00\00\e4\01\10\00^\00\00\00z\02\00\00\0d\00\00\00/home/hexular/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/wasm-bindgen-0.2.101/src/convert/slices.rs\00\00\00|\02\10\00m\00\00\00\e8\00\00\00\01\00\00\00memory allocation of  bytes failed\00\00\fc\02\10\00\15\00\00\00\11\03\10\00\0d\00\00\00library/std/src/alloc.rs0\03\10\00\18\00\00\00d\01\00\00\09\00\00\00/build/rustc-1.87.0-src/library/alloc/src/raw_vec/mod.rsX\03\10\008\00\00\00.\02\00\00\11\00\00\00/build/rustc-1.87.0-src/library/alloc/src/string.rs\00\a0\03\10\003\00\00\00}\05\00\00\1b\00\00\00\05\00\00\00\0c\00\00\00\04\00\00\00\06\00\00\00\07\00\00\00\08\00\00\00\05\00\00\00\0c\00\00\00\04\00\00\00\09\00\00\00\00\00\00\00\08\00\00\00\04\00\00\00\0a\00\00\00/build/rustc-1.87.0-src/vendor/dlmalloc-0.2.7/src/dlmalloc.rsassertion failed: psize >= size + min_overhead\00\1c\04\10\00=\00\00\00\a8\04\00\00\09\00\00\00assertion failed: psize <= size + max_overhead\00\00\1c\04\10\00=\00\00\00\ae\04\00\00\0d\00\00\00\00\00\00\00\08\00\00\00\04\00\00\00\0a\00\00\00\00\00\00\00\08\00\00\00\04\00\00\00\0b\00\00\00\0c\00\00\00\0d\00\00\00\0e\00\00\00\0f\00\00\00\10\00\00\00\04\00\00\00\10\00\00\00\11\00\00\00\12\00\00\00\13\00\00\00capacity overflow\00\00\00 \05\10\00\11\00\00\0000010203040506070809101112131415161718192021222324252627282930313233343536373839404142434445464748495051525354555657585960616263646566676869707172737475767778798081828384858687888990919293949596979899index out of bounds: the len is  but the index is \00\00\04\06\10\00 \00\00\00$\06\10\00\12\00\00\00: \00\00\01\00\00\00\00\00\00\00H\06\10\00\02")
  (data (;1;) (i32.const 1050228) "\02"))
