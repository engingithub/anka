use super::tests::protected_frame_fixture;
use super::*;

fn stack(core: &Anka64Core, f: &Fabric) -> u64 {
    let s = core.pointer_frames.as_ref().unwrap();
    f.translate(s.stack_object, s.stack_offset).unwrap()
}
#[test]
fn r1_fresh_local_reads_zero_and_retired_register_alias_stays_dead() {
    let (mut f, mut c, exit) = protected_frame_fixture();
    let base = stack(&c, &f);
    f.write_physical(base, &[0xa7; 4096]);
    c.enter_pointer_frame(&mut f, 0).unwrap();
    c.lookup_pointer_local(&f, R4, 0).unwrap();
    let old = c.captured_pointer(R4).unwrap().unwrap();
    assert_eq!(c.pointer_read(&mut f, R4, Width::Byte).unwrap(), vec![0]);
    c.lookup_pointer_local(&f, R8, 1).unwrap();
    assert_eq!(f.read_physical(base + 4096 - 32, 32), [0; 32]);
    f.write_physical(base + 4096 - 32, &[0xa7; 32]);
    c.pc = exit as u64 * 4;
    c.leave_pointer_frame(&mut f).unwrap();
    c.pc = 0;
    c.pointer_frames.as_mut().unwrap().pending_entry = Some(0);
    c.enter_pointer_frame(&mut f, 0).unwrap();
    c.lookup_pointer_local(&f, R4, 0).unwrap();
    assert_eq!(c.pointer_read(&mut f, R4, Width::Byte).unwrap(), vec![0]);
    assert!(f.scoped_pointer_backing(old, c.domain).is_err());
}
#[test]
fn r1_nested_entry_preserves_register_arguments_kinds_and_parent_storage() {
    let (mut f, mut c, _) = protected_frame_fixture();
    let entry = c.pointer_frames.as_ref().unwrap().program.frames[1].entry;
    for _ in 0..20 {
        if c.pc == entry {
            break;
        }
        assert!(matches!(c.step(&mut f), StepResult::Continue));
    }
    assert_eq!(c.pc, entry);
    let words = c.r;
    let kinds = c.pointer_pairs;
    let flags = format!("{:?}", c.flags);
    let depth = c.return_stack.len();
    let parent = c.pointer_frames.as_ref().unwrap().cursor;
    let (obj, off) = c.address_map.resolve(parent).unwrap();
    let physical = f.translate(obj, off).unwrap();
    let before = f.read_physical(physical, 32).to_vec();
    f.write_physical(physical - 16, &[0x55; 16]);
    c.enter_pointer_frame(&mut f, 1).unwrap();
    for i in 0..16 {
        if i != SP as usize && i != FP as usize {
            assert_eq!(c.r[i], words[i]);
        }
    }
    assert_eq!(c.pointer_pairs, kinds);
    assert_eq!(format!("{:?}", c.flags), flags);
    assert_eq!(c.return_stack.len(), depth);
    assert_eq!(f.read_physical(physical, 32), before);
    assert_eq!(f.read_physical(physical - 16, 16), [0; 16]);
}
#[test]
fn r1_nested_event_restore_does_not_scrub_or_release_suspended_frame() {
    let (mut f, mut c, _) = protected_frame_fixture();
    c.enter_pointer_frame(&mut f, 0).unwrap();
    c.lookup_pointer_local(&f, R4, 0).unwrap();
    let pointer = c.captured_pointer(R4).unwrap().unwrap();
    let (obj, off) = f.scoped_pointer_backing(pointer, c.domain).unwrap();
    let physical = f.translate(obj, off).unwrap();
    f.write_physical(physical, &[71]);
    let before = format!("{:?}", f.scoped_pointers);
    c.enter_event(EventFrame {
        return_pc: 4,
        return_privilege: Privilege::User,
        interrupts_were_enabled: true,
        cause: EventCause::TimerInterrupt,
    });
    c.enter_event(EventFrame {
        return_pc: 8,
        return_privilege: Privilege::Supervisor,
        interrupts_were_enabled: false,
        cause: EventCause::TimerInterrupt,
    });
    assert!(c.enter_pointer_frame(&mut f, 0).is_err());
    assert_eq!(c.event_return(), Some(8));
    assert_eq!(c.event_return(), Some(4));
    assert_eq!(format!("{:?}", f.scoped_pointers), before);
    assert_eq!(c.pointer_read(&mut f, R4, Width::Byte).unwrap(), vec![71]);
    c.retire_all_pointer_frames(&mut f);
    assert!(f.scoped_pointer_backing(pointer, c.domain).is_err());
}
#[test]
fn r1_failed_frame_capacity_preserves_cursor_registers_and_dirty_storage() {
    let (mut f, mut c, _) = protected_frame_fixture();
    f.scoped_pointers = crate::anka64::scoped_pointers::ScopedPointers::new(1);
    let base = stack(&c, &f);
    f.write_physical(base, &[0xa7; 4096]);
    let words = c.r;
    let kinds = c.pointer_pairs;
    let frames = format!("{:?}", c.pointer_frames);
    assert!(c.enter_pointer_frame(&mut f, 0).is_err());
    assert_eq!(c.r, words);
    assert_eq!(c.pointer_pairs, kinds);
    assert_eq!(format!("{:?}", c.pointer_frames), frames);
    assert_eq!(f.read_physical(base, 4096), [0xa7; 4096]);
}
#[test]
fn r1_stack_generation_change_cannot_rebind_existing_admission() {
    let (mut f, mut c, _) = protected_frame_fixture();
    let obj = c.pointer_frames.as_ref().unwrap().stack_object;
    let base = stack(&c, &f);
    f.write_physical(base, &[0xa7; 4096]);
    let old = f.objects[&obj].generation;
    f.objects.get_mut(&obj).unwrap().generation = Generation(old.0 + 1);
    let words = c.r;
    assert!(c.enter_pointer_frame(&mut f, 0).is_err());
    assert_eq!(c.r, words);
    assert_eq!(f.read_physical(base, 4096), [0xa7; 4096]);
}
