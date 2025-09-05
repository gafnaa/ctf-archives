undefined8 FUN_00402056(void)


{
  bool bVar1;
  int iVar2;
  long lVar3;
  undefined8 uVar4;
  long in_FS_OFFSET;
  int local_4c;
  int local_48;
  undefined1 local_38 [40];
  long local_10;

  

  local_10 = *(long *)(in_FS_OFFSET + 0x28);

  FUN_0044c870("Flag: ");

  FUN_0044c7a0(&DAT_004e9037,local_38);

  lVar3 = thunk_FUN_0046ecc0(local_38);

  if (lVar3 != 0x21) {

    FUN_0045c920("WRONG");

    uVar4 = 1;

LAB_00402261:

    if (local_10 == *(long *)(in_FS_OFFSET + 0x28)) {

      return uVar4;

    }

                    /* WARNING: Subroutine does not return */

    FUN_00492140();

  }

  local_4c = 0;

  while( true ) {

    if (0x48a < local_4c) goto LAB_0040212a;

    if ((&DAT_0054cc00)[local_4c] == '*') break;

    local_4c = local_4c + 1;

  }

  for (local_48 = 0; local_48 < 0x21; local_48 = local_48 + 1) {

    (&DAT_0054cc00)[local_4c + local_48] = local_38[local_48];

  }

LAB_0040212a:

  lVar3 = FUN_0041c650();

  if (lVar3 == 0) {

    uVar4 = 1;

  }

  else {

    FUN_0041c730(lVar3);

    FUN_00403b70(lVar3,FUN_00401f24,0);

    FUN_00404380(lVar3,&DAT_0054cba0);

    FUN_00403b70(lVar3,FUN_00401f8a,0);

    FUN_00404380(lVar3,&DAT_0054cbc0);

    FUN_00403b70(lVar3,FUN_00401ff0,0);

    FUN_00404380(lVar3,&DAT_0054cbe0);

    iVar2 = FUN_0041b6f0(lVar3,&DAT_0054cc00);

    if ((iVar2 == 0) && (iVar2 = FUN_00404a40(lVar3,0,0xffffffff,0,0,0), iVar2 == 0)) {

      bVar1 = false;

    }

    else {

      bVar1 = true;

    }

    if (bVar1) {

      FUN_00411090(lVar3);

      uVar4 = 1;

    }

    else {

      FUN_00411090(lVar3);

      uVar4 = 0;

    }

  }

  goto LAB_00402261;

}